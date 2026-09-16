rule TTP_XOR_QUAD_CurrentVersionRun_01d0 {
  strings:
    $key_01d0 = { 52 bf [2] 76 b1 [2] 5d 9d [2] 73 bf [2] 67 a4 [2] 68 be [2] 76 a3 [2] 74 a2 [2] 6f a4 [2] 73 a3 [2] 6f 8c }

  condition:
    any of them
}