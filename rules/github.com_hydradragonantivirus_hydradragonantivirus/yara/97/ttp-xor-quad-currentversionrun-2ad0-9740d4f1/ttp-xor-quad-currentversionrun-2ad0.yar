rule TTP_XOR_QUAD_CurrentVersionRun_2ad0 {
  strings:
    $key_2ad0 = { 79 bf [2] 5d b1 [2] 76 9d [2] 58 bf [2] 4c a4 [2] 43 be [2] 5d a3 [2] 5f a2 [2] 44 a4 [2] 58 a3 [2] 44 8c }

  condition:
    any of them
}