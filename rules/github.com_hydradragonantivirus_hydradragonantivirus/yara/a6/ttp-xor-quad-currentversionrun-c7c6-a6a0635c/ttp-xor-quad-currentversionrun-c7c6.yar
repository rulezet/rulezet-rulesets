rule TTP_XOR_QUAD_CurrentVersionRun_c7c6 {
  strings:
    $key_c7c6 = { 94 a9 [2] b0 a7 [2] 9b 8b [2] b5 a9 [2] a1 b2 [2] ae a8 [2] b0 b5 [2] b2 b4 [2] a9 b2 [2] b5 b5 [2] a9 9a }

  condition:
    any of them
}