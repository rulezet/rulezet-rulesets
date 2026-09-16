rule TTP_XOR_QUAD_CurrentVersionRun_27d0 {
  strings:
    $key_27d0 = { 74 bf [2] 50 b1 [2] 7b 9d [2] 55 bf [2] 41 a4 [2] 4e be [2] 50 a3 [2] 52 a2 [2] 49 a4 [2] 55 a3 [2] 49 8c }

  condition:
    any of them
}