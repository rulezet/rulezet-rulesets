rule TTP_XOR_QUAD_CurrentVersionRun_4567 {
  strings:
    $key_4567 = { 16 08 [2] 32 06 [2] 19 2a [2] 37 08 [2] 23 13 [2] 2c 09 [2] 32 14 [2] 30 15 [2] 2b 13 [2] 37 14 [2] 2b 3b }

  condition:
    any of them
}