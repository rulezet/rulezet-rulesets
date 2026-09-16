rule TTP_XOR_QUAD_CurrentVersionRun_7c47 {
  strings:
    $key_7c47 = { 2f 28 [2] 0b 26 [2] 20 0a [2] 0e 28 [2] 1a 33 [2] 15 29 [2] 0b 34 [2] 09 35 [2] 12 33 [2] 0e 34 [2] 12 1b }

  condition:
    any of them
}