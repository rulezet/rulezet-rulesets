rule TTP_XOR_QUAD_CurrentVersionRun_7bca {
  strings:
    $key_7bca = { 28 a5 [2] 0c ab [2] 27 87 [2] 09 a5 [2] 1d be [2] 12 a4 [2] 0c b9 [2] 0e b8 [2] 15 be [2] 09 b9 [2] 15 96 }

  condition:
    any of them
}