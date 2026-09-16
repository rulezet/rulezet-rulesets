rule TTP_XOR_QUAD_CurrentVersionRun_e7d0 {
  strings:
    $key_e7d0 = { b4 bf [2] 90 b1 [2] bb 9d [2] 95 bf [2] 81 a4 [2] 8e be [2] 90 a3 [2] 92 a2 [2] 89 a4 [2] 95 a3 [2] 89 8c }

  condition:
    any of them
}