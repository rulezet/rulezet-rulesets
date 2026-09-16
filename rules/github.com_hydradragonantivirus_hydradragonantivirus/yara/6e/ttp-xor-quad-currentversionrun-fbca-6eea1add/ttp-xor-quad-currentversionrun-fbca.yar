rule TTP_XOR_QUAD_CurrentVersionRun_fbca {
  strings:
    $key_fbca = { a8 a5 [2] 8c ab [2] a7 87 [2] 89 a5 [2] 9d be [2] 92 a4 [2] 8c b9 [2] 8e b8 [2] 95 be [2] 89 b9 [2] 95 96 }

  condition:
    any of them
}