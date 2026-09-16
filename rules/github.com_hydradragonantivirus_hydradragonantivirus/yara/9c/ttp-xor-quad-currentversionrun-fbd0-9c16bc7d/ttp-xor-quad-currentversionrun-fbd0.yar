rule TTP_XOR_QUAD_CurrentVersionRun_fbd0 {
  strings:
    $key_fbd0 = { a8 bf [2] 8c b1 [2] a7 9d [2] 89 bf [2] 9d a4 [2] 92 be [2] 8c a3 [2] 8e a2 [2] 95 a4 [2] 89 a3 [2] 95 8c }

  condition:
    any of them
}