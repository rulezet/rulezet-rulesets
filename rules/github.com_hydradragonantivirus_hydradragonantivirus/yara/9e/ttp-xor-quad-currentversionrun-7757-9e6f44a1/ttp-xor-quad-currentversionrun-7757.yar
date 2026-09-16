rule TTP_XOR_QUAD_CurrentVersionRun_7757 {
  strings:
    $key_7757 = { 24 38 [2] 00 36 [2] 2b 1a [2] 05 38 [2] 11 23 [2] 1e 39 [2] 00 24 [2] 02 25 [2] 19 23 [2] 05 24 [2] 19 0b }

  condition:
    any of them
}