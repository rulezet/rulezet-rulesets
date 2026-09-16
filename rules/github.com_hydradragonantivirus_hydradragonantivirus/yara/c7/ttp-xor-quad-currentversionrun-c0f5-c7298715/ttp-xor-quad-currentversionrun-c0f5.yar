rule TTP_XOR_QUAD_CurrentVersionRun_c0f5 {
  strings:
    $key_c0f5 = { 93 9a [2] b7 94 [2] 9c b8 [2] b2 9a [2] a6 81 [2] a9 9b [2] b7 86 [2] b5 87 [2] ae 81 [2] b2 86 [2] ae a9 }

  condition:
    any of them
}