rule TTP_XOR_QUAD_CurrentVersionRun_64d0 {
  strings:
    $key_64d0 = { 37 bf [2] 13 b1 [2] 38 9d [2] 16 bf [2] 02 a4 [2] 0d be [2] 13 a3 [2] 11 a2 [2] 0a a4 [2] 16 a3 [2] 0a 8c }

  condition:
    any of them
}