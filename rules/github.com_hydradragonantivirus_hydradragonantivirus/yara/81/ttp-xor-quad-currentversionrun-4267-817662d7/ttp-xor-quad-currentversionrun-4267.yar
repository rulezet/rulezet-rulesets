rule TTP_XOR_QUAD_CurrentVersionRun_4267 {
  strings:
    $key_4267 = { 11 08 [2] 35 06 [2] 1e 2a [2] 30 08 [2] 24 13 [2] 2b 09 [2] 35 14 [2] 37 15 [2] 2c 13 [2] 30 14 [2] 2c 3b }

  condition:
    any of them
}