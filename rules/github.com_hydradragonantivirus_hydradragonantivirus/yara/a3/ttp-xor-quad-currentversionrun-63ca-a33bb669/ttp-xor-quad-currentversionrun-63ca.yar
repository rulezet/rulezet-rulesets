rule TTP_XOR_QUAD_CurrentVersionRun_63ca {
  strings:
    $key_63ca = { 30 a5 [2] 14 ab [2] 3f 87 [2] 11 a5 [2] 05 be [2] 0a a4 [2] 14 b9 [2] 16 b8 [2] 0d be [2] 11 b9 [2] 0d 96 }

  condition:
    any of them
}