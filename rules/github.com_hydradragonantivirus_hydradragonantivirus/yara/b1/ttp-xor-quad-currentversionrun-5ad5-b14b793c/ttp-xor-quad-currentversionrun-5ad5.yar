rule TTP_XOR_QUAD_CurrentVersionRun_5ad5 {
  strings:
    $key_5ad5 = { 09 ba [2] 2d b4 [2] 06 98 [2] 28 ba [2] 3c a1 [2] 33 bb [2] 2d a6 [2] 2f a7 [2] 34 a1 [2] 28 a6 [2] 34 89 }

  condition:
    any of them
}