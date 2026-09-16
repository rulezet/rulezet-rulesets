rule TTP_XOR_QUAD_CurrentVersionRun_c0d7 {
  strings:
    $key_c0d7 = { 93 b8 [2] b7 b6 [2] 9c 9a [2] b2 b8 [2] a6 a3 [2] a9 b9 [2] b7 a4 [2] b5 a5 [2] ae a3 [2] b2 a4 [2] ae 8b }

  condition:
    any of them
}