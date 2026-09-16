rule TTP_XOR_QUAD_CurrentVersionRun_5ad0 {
  strings:
    $key_5ad0 = { 09 bf [2] 2d b1 [2] 06 9d [2] 28 bf [2] 3c a4 [2] 33 be [2] 2d a3 [2] 2f a2 [2] 34 a4 [2] 28 a3 [2] 34 8c }

  condition:
    any of them
}