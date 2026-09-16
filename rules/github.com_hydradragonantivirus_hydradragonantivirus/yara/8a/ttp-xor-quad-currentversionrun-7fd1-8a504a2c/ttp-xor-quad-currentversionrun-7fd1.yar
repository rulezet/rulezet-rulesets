rule TTP_XOR_QUAD_CurrentVersionRun_7fd1 {
  strings:
    $key_7fd1 = { 2c be [2] 08 b0 [2] 23 9c [2] 0d be [2] 19 a5 [2] 16 bf [2] 08 a2 [2] 0a a3 [2] 11 a5 [2] 0d a2 [2] 11 8d }

  condition:
    any of them
}