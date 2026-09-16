rule TTP_XOR_QUAD_CurrentVersionRun_1ed1 {
  strings:
    $key_1ed1 = { 4d be [2] 69 b0 [2] 42 9c [2] 6c be [2] 78 a5 [2] 77 bf [2] 69 a2 [2] 6b a3 [2] 70 a5 [2] 6c a2 [2] 70 8d }

  condition:
    any of them
}