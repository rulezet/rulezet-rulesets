rule TTP_XOR_QUAD_CurrentVersionRun_c0f8 {
  strings:
    $key_c0f8 = { 93 97 [2] b7 99 [2] 9c b5 [2] b2 97 [2] a6 8c [2] a9 96 [2] b7 8b [2] b5 8a [2] ae 8c [2] b2 8b [2] ae a4 }

  condition:
    any of them
}