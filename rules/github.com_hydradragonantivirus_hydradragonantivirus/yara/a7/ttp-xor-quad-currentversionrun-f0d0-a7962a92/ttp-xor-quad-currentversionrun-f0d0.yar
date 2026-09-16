rule TTP_XOR_QUAD_CurrentVersionRun_f0d0 {
  strings:
    $key_f0d0 = { a3 bf [2] 87 b1 [2] ac 9d [2] 82 bf [2] 96 a4 [2] 99 be [2] 87 a3 [2] 85 a2 [2] 9e a4 [2] 82 a3 [2] 9e 8c }

  condition:
    any of them
}