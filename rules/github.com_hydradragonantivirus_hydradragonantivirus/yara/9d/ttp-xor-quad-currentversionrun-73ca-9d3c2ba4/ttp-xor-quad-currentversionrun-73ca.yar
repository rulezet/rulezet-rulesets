rule TTP_XOR_QUAD_CurrentVersionRun_73ca {
  strings:
    $key_73ca = { 20 a5 [2] 04 ab [2] 2f 87 [2] 01 a5 [2] 15 be [2] 1a a4 [2] 04 b9 [2] 06 b8 [2] 1d be [2] 01 b9 [2] 1d 96 }

  condition:
    any of them
}