rule TTP_XOR_QUAD_CurrentVersionRun_c0f4 {
  strings:
    $key_c0f4 = { 93 9b [2] b7 95 [2] 9c b9 [2] b2 9b [2] a6 80 [2] a9 9a [2] b7 87 [2] b5 86 [2] ae 80 [2] b2 87 [2] ae a8 }

  condition:
    any of them
}