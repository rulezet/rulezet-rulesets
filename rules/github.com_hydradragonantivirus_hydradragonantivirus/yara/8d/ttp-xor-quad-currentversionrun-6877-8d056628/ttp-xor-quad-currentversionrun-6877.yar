rule TTP_XOR_QUAD_CurrentVersionRun_6877 {
  strings:
    $key_6877 = { 3b 18 [2] 1f 16 [2] 34 3a [2] 1a 18 [2] 0e 03 [2] 01 19 [2] 1f 04 [2] 1d 05 [2] 06 03 [2] 1a 04 [2] 06 2b }

  condition:
    any of them
}