rule TTP_XOR_QUAD_CurrentVersionRun_0bca {
  strings:
    $key_0bca = { 58 a5 [2] 7c ab [2] 57 87 [2] 79 a5 [2] 6d be [2] 62 a4 [2] 7c b9 [2] 7e b8 [2] 65 be [2] 79 b9 [2] 65 96 }

  condition:
    any of them
}