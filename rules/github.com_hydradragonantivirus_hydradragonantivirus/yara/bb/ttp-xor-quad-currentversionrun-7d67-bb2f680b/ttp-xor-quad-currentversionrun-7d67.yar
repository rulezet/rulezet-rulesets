rule TTP_XOR_QUAD_CurrentVersionRun_7d67 {
  strings:
    $key_7d67 = { 2e 08 [2] 0a 06 [2] 21 2a [2] 0f 08 [2] 1b 13 [2] 14 09 [2] 0a 14 [2] 08 15 [2] 13 13 [2] 0f 14 [2] 13 3b }

  condition:
    any of them
}