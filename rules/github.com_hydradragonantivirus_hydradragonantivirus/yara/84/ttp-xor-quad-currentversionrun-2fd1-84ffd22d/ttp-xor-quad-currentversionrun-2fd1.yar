rule TTP_XOR_QUAD_CurrentVersionRun_2fd1 {
  strings:
    $key_2fd1 = { 7c be [2] 58 b0 [2] 73 9c [2] 5d be [2] 49 a5 [2] 46 bf [2] 58 a2 [2] 5a a3 [2] 41 a5 [2] 5d a2 [2] 41 8d }

  condition:
    any of them
}