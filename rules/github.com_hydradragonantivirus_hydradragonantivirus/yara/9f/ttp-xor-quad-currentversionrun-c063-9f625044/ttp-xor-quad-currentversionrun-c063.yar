rule TTP_XOR_QUAD_CurrentVersionRun_c063 {
  strings:
    $key_c063 = { 93 0c [2] b7 02 [2] 9c 2e [2] b2 0c [2] a6 17 [2] a9 0d [2] b7 10 [2] b5 11 [2] ae 17 [2] b2 10 [2] ae 3f }

  condition:
    any of them
}