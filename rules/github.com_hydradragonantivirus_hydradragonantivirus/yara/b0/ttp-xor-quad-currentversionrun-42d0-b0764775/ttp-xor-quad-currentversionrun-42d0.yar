rule TTP_XOR_QUAD_CurrentVersionRun_42d0 {
  strings:
    $key_42d0 = { 11 bf [2] 35 b1 [2] 1e 9d [2] 30 bf [2] 24 a4 [2] 2b be [2] 35 a3 [2] 37 a2 [2] 2c a4 [2] 30 a3 [2] 2c 8c }

  condition:
    any of them
}