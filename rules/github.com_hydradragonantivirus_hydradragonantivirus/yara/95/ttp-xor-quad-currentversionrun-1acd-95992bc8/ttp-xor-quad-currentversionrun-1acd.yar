rule TTP_XOR_QUAD_CurrentVersionRun_1acd {
  strings:
    $key_1acd = { 49 a2 [2] 6d ac [2] 46 80 [2] 68 a2 [2] 7c b9 [2] 73 a3 [2] 6d be [2] 6f bf [2] 74 b9 [2] 68 be [2] 74 91 }

  condition:
    any of them
}