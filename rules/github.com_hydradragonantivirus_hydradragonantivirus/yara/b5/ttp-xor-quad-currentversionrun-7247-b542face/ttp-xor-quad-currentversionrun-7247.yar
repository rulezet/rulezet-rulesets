rule TTP_XOR_QUAD_CurrentVersionRun_7247 {
  strings:
    $key_7247 = { 21 28 [2] 05 26 [2] 2e 0a [2] 00 28 [2] 14 33 [2] 1b 29 [2] 05 34 [2] 07 35 [2] 1c 33 [2] 00 34 [2] 1c 1b }

  condition:
    any of them
}