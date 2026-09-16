rule TTP_XOR_QUAD_CurrentVersionRun_6acd {
  strings:
    $key_6acd = { 39 a2 [2] 1d ac [2] 36 80 [2] 18 a2 [2] 0c b9 [2] 03 a3 [2] 1d be [2] 1f bf [2] 04 b9 [2] 18 be [2] 04 91 }

  condition:
    any of them
}