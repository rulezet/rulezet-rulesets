rule TTP_XOR_QUAD_CurrentVersionRun_7d5b {
  strings:
    $key_7d5b = { 2e 34 [2] 0a 3a [2] 21 16 [2] 0f 34 [2] 1b 2f [2] 14 35 [2] 0a 28 [2] 08 29 [2] 13 2f [2] 0f 28 [2] 13 07 }

  condition:
    any of them
}