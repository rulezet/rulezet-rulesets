rule TTP_XOR_QUAD_CurrentVersionRun_0fd1 {
  strings:
    $key_0fd1 = { 5c be [2] 78 b0 [2] 53 9c [2] 7d be [2] 69 a5 [2] 66 bf [2] 78 a2 [2] 7a a3 [2] 61 a5 [2] 7d a2 [2] 61 8d }

  condition:
    any of them
}