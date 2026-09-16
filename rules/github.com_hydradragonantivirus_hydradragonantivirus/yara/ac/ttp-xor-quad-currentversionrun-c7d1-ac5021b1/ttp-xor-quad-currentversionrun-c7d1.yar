rule TTP_XOR_QUAD_CurrentVersionRun_c7d1 {
  strings:
    $key_c7d1 = { 94 be [2] b0 b0 [2] 9b 9c [2] b5 be [2] a1 a5 [2] ae bf [2] b0 a2 [2] b2 a3 [2] a9 a5 [2] b5 a2 [2] a9 8d }

  condition:
    any of them
}