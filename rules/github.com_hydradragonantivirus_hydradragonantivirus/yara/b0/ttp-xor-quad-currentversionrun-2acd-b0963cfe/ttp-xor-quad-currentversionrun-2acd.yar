rule TTP_XOR_QUAD_CurrentVersionRun_2acd {
  strings:
    $key_2acd = { 79 a2 [2] 5d ac [2] 76 80 [2] 58 a2 [2] 4c b9 [2] 43 a3 [2] 5d be [2] 5f bf [2] 44 b9 [2] 58 be [2] 44 91 }

  condition:
    any of them
}