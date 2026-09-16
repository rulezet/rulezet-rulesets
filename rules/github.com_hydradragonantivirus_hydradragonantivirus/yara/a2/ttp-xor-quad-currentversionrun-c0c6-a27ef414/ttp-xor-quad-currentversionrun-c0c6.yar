rule TTP_XOR_QUAD_CurrentVersionRun_c0c6 {
  strings:
    $key_c0c6 = { 93 a9 [2] b7 a7 [2] 9c 8b [2] b2 a9 [2] a6 b2 [2] a9 a8 [2] b7 b5 [2] b5 b4 [2] ae b2 [2] b2 b5 [2] ae 9a }

  condition:
    any of them
}