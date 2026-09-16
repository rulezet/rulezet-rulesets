rule TTP_XOR_QUAD_CurrentVersionRun_c7d7 {
  strings:
    $key_c7d7 = { 94 b8 [2] b0 b6 [2] 9b 9a [2] b5 b8 [2] a1 a3 [2] ae b9 [2] b0 a4 [2] b2 a5 [2] a9 a3 [2] b5 a4 [2] a9 8b }

  condition:
    any of them
}