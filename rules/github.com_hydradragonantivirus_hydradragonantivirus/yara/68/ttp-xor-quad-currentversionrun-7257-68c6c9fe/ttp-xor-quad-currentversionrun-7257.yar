rule TTP_XOR_QUAD_CurrentVersionRun_7257 {
  strings:
    $key_7257 = { 21 38 [2] 05 36 [2] 2e 1a [2] 00 38 [2] 14 23 [2] 1b 39 [2] 05 24 [2] 07 25 [2] 1c 23 [2] 00 24 [2] 1c 0b }

  condition:
    any of them
}