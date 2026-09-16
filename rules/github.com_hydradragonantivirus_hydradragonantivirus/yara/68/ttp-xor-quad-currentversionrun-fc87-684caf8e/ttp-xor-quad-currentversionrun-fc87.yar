rule TTP_XOR_QUAD_CurrentVersionRun_fc87 {
  strings:
    $key_fc87 = { af e8 [2] 8b e6 [2] a0 ca [2] 8e e8 [2] 9a f3 [2] 95 e9 [2] 8b f4 [2] 89 f5 [2] 92 f3 [2] 8e f4 [2] 92 db }

  condition:
    any of them
}