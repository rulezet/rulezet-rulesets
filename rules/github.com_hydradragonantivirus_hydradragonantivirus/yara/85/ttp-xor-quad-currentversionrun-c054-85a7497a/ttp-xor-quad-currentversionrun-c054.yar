rule TTP_XOR_QUAD_CurrentVersionRun_c054 {
  strings:
    $key_c054 = { 93 3b [2] b7 35 [2] 9c 19 [2] b2 3b [2] a6 20 [2] a9 3a [2] b7 27 [2] b5 26 [2] ae 20 [2] b2 27 [2] ae 08 }

  condition:
    any of them
}