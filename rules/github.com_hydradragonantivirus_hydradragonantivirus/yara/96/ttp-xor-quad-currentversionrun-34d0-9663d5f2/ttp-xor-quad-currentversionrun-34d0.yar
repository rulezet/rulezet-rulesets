rule TTP_XOR_QUAD_CurrentVersionRun_34d0 {
  strings:
    $key_34d0 = { 67 bf [2] 43 b1 [2] 68 9d [2] 46 bf [2] 52 a4 [2] 5d be [2] 43 a3 [2] 41 a2 [2] 5a a4 [2] 46 a3 [2] 5a 8c }

  condition:
    any of them
}