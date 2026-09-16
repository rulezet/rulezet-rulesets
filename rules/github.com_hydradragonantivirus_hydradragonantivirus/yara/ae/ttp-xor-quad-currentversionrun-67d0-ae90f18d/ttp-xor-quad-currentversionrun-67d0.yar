rule TTP_XOR_QUAD_CurrentVersionRun_67d0 {
  strings:
    $key_67d0 = { 34 bf [2] 10 b1 [2] 3b 9d [2] 15 bf [2] 01 a4 [2] 0e be [2] 10 a3 [2] 12 a2 [2] 09 a4 [2] 15 a3 [2] 09 8c }

  condition:
    any of them
}