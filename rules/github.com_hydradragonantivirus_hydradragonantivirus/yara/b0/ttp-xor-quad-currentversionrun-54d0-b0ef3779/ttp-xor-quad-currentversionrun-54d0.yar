rule TTP_XOR_QUAD_CurrentVersionRun_54d0 {
  strings:
    $key_54d0 = { 07 bf [2] 23 b1 [2] 08 9d [2] 26 bf [2] 32 a4 [2] 3d be [2] 23 a3 [2] 21 a2 [2] 3a a4 [2] 26 a3 [2] 3a 8c }

  condition:
    any of them
}