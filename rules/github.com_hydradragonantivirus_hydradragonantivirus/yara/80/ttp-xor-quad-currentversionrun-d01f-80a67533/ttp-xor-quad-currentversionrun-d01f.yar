rule TTP_XOR_QUAD_CurrentVersionRun_d01f {
  strings:
    $key_d01f = { 83 70 [2] a7 7e [2] 8c 52 [2] a2 70 [2] b6 6b [2] b9 71 [2] a7 6c [2] a5 6d [2] be 6b [2] a2 6c [2] be 43 }

  condition:
    any of them
}