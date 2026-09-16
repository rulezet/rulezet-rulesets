rule TTP_XOR_QUAD_CurrentVersionRun_41d0 {
  strings:
    $key_41d0 = { 12 bf [2] 36 b1 [2] 1d 9d [2] 33 bf [2] 27 a4 [2] 28 be [2] 36 a3 [2] 34 a2 [2] 2f a4 [2] 33 a3 [2] 2f 8c }

  condition:
    any of them
}