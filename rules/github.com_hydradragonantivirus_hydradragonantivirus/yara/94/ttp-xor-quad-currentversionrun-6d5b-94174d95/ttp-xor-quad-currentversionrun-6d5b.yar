rule TTP_XOR_QUAD_CurrentVersionRun_6d5b {
  strings:
    $key_6d5b = { 3e 34 [2] 1a 3a [2] 31 16 [2] 1f 34 [2] 0b 2f [2] 04 35 [2] 1a 28 [2] 18 29 [2] 03 2f [2] 1f 28 [2] 03 07 }

  condition:
    any of them
}