rule TTP_XOR_QUAD_CurrentVersionRun_4ad0 {
  strings:
    $key_4ad0 = { 19 bf [2] 3d b1 [2] 16 9d [2] 38 bf [2] 2c a4 [2] 23 be [2] 3d a3 [2] 3f a2 [2] 24 a4 [2] 38 a3 [2] 24 8c }

  condition:
    any of them
}