rule TTP_XOR_QUAD_CurrentVersionRun_5567 {
  strings:
    $key_5567 = { 06 08 [2] 22 06 [2] 09 2a [2] 27 08 [2] 33 13 [2] 3c 09 [2] 22 14 [2] 20 15 [2] 3b 13 [2] 27 14 [2] 3b 3b }

  condition:
    any of them
}