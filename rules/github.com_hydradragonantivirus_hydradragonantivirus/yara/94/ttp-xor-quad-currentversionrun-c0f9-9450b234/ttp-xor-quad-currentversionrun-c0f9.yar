rule TTP_XOR_QUAD_CurrentVersionRun_c0f9 {
  strings:
    $key_c0f9 = { 93 96 [2] b7 98 [2] 9c b4 [2] b2 96 [2] a6 8d [2] a9 97 [2] b7 8a [2] b5 8b [2] ae 8d [2] b2 8a [2] ae a5 }

  condition:
    any of them
}