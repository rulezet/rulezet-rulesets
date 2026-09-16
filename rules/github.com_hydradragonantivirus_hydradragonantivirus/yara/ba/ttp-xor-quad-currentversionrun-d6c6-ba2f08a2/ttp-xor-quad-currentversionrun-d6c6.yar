rule TTP_XOR_QUAD_CurrentVersionRun_d6c6 {
  strings:
    $key_d6c6 = { 85 a9 [2] a1 a7 [2] 8a 8b [2] a4 a9 [2] b0 b2 [2] bf a8 [2] a1 b5 [2] a3 b4 [2] b8 b2 [2] a4 b5 [2] b8 9a }

  condition:
    any of them
}