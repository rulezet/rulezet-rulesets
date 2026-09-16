rule TTP_XOR_QUAD_CurrentVersionRun_6847 {
  strings:
    $key_6847 = { 3b 28 [2] 1f 26 [2] 34 0a [2] 1a 28 [2] 0e 33 [2] 01 29 [2] 1f 34 [2] 1d 35 [2] 06 33 [2] 1a 34 [2] 06 1b }

  condition:
    any of them
}