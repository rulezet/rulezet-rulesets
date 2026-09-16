rule TTP_XOR_QUAD_CurrentVersionRun_d02f {
  strings:
    $key_d02f = { 83 40 [2] a7 4e [2] 8c 62 [2] a2 40 [2] b6 5b [2] b9 41 [2] a7 5c [2] a5 5d [2] be 5b [2] a2 5c [2] be 73 }

  condition:
    any of them
}