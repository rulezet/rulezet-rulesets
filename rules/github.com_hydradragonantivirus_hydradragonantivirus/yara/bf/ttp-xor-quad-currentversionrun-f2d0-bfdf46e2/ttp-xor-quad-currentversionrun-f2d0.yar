rule TTP_XOR_QUAD_CurrentVersionRun_f2d0 {
  strings:
    $key_f2d0 = { a1 bf [2] 85 b1 [2] ae 9d [2] 80 bf [2] 94 a4 [2] 9b be [2] 85 a3 [2] 87 a2 [2] 9c a4 [2] 80 a3 [2] 9c 8c }

  condition:
    any of them
}