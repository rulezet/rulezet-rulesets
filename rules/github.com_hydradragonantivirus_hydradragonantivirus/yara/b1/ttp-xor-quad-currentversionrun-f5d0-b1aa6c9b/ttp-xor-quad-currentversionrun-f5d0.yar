rule TTP_XOR_QUAD_CurrentVersionRun_f5d0 {
  strings:
    $key_f5d0 = { a6 bf [2] 82 b1 [2] a9 9d [2] 87 bf [2] 93 a4 [2] 9c be [2] 82 a3 [2] 80 a2 [2] 9b a4 [2] 87 a3 [2] 9b 8c }

  condition:
    any of them
}