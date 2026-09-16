rule TTP_XOR_QUAD_CurrentVersionRun_6ad0 {
  strings:
    $key_6ad0 = { 39 bf [2] 1d b1 [2] 36 9d [2] 18 bf [2] 0c a4 [2] 03 be [2] 1d a3 [2] 1f a2 [2] 04 a4 [2] 18 a3 [2] 04 8c }

  condition:
    any of them
}