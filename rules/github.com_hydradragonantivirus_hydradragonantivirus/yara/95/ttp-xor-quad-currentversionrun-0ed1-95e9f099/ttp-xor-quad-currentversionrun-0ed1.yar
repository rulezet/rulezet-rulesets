rule TTP_XOR_QUAD_CurrentVersionRun_0ed1 {
  strings:
    $key_0ed1 = { 5d be [2] 79 b0 [2] 52 9c [2] 7c be [2] 68 a5 [2] 67 bf [2] 79 a2 [2] 7b a3 [2] 60 a5 [2] 7c a2 [2] 60 8d }

  condition:
    any of them
}