rule TTP_XOR_QUAD_CurrentVersionRun_20d0 {
  strings:
    $key_20d0 = { 73 bf [2] 57 b1 [2] 7c 9d [2] 52 bf [2] 46 a4 [2] 49 be [2] 57 a3 [2] 55 a2 [2] 4e a4 [2] 52 a3 [2] 4e 8c }

  condition:
    any of them
}