rule TTP_XOR_QUAD_CurrentVersionRun_0dd5 {
  strings:
    $key_0dd5 = { 5e ba [2] 7a b4 [2] 51 98 [2] 7f ba [2] 6b a1 [2] 64 bb [2] 7a a6 [2] 78 a7 [2] 63 a1 [2] 7f a6 [2] 63 89 }

  condition:
    any of them
}