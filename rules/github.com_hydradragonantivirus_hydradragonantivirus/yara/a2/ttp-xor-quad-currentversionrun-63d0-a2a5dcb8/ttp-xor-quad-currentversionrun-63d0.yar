rule TTP_XOR_QUAD_CurrentVersionRun_63d0 {
  strings:
    $key_63d0 = { 30 bf [2] 14 b1 [2] 3f 9d [2] 11 bf [2] 05 a4 [2] 0a be [2] 14 a3 [2] 16 a2 [2] 0d a4 [2] 11 a3 [2] 0d 8c }

  condition:
    any of them
}