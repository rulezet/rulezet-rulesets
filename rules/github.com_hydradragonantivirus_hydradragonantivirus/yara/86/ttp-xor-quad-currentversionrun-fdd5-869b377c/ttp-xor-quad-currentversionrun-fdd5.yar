rule TTP_XOR_QUAD_CurrentVersionRun_fdd5 {
  strings:
    $key_fdd5 = { ae ba [2] 8a b4 [2] a1 98 [2] 8f ba [2] 9b a1 [2] 94 bb [2] 8a a6 [2] 88 a7 [2] 93 a1 [2] 8f a6 [2] 93 89 }

  condition:
    any of them
}