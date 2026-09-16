rule TTP_XOR_QUAD_CurrentVersionRun_1bca {
  strings:
    $key_1bca = { 48 a5 [2] 6c ab [2] 47 87 [2] 69 a5 [2] 7d be [2] 72 a4 [2] 6c b9 [2] 6e b8 [2] 75 be [2] 69 b9 [2] 75 96 }

  condition:
    any of them
}