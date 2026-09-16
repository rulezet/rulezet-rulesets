rule TTP_XOR_QUAD_CurrentVersionRun_d03f {
  strings:
    $key_d03f = { 83 50 [2] a7 5e [2] 8c 72 [2] a2 50 [2] b6 4b [2] b9 51 [2] a7 4c [2] a5 4d [2] be 4b [2] a2 4c [2] be 63 }

  condition:
    any of them
}