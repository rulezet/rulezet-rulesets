rule TTP_XOR_QUAD_CurrentVersionRun_fc88 {
  strings:
    $key_fc88 = { af e7 [2] 8b e9 [2] a0 c5 [2] 8e e7 [2] 9a fc [2] 95 e6 [2] 8b fb [2] 89 fa [2] 92 fc [2] 8e fb [2] 92 d4 }

  condition:
    any of them
}