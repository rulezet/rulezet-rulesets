rule TTP_XOR_QUAD_CurrentVersionRun_6fd1 {
  strings:
    $key_6fd1 = { 3c be [2] 18 b0 [2] 33 9c [2] 1d be [2] 09 a5 [2] 06 bf [2] 18 a2 [2] 1a a3 [2] 01 a5 [2] 1d a2 [2] 01 8d }

  condition:
    any of them
}