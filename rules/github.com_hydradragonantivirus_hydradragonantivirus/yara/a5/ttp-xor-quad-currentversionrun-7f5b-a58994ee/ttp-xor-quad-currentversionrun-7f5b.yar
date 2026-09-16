rule TTP_XOR_QUAD_CurrentVersionRun_7f5b {
  strings:
    $key_7f5b = { 2c 34 [2] 08 3a [2] 23 16 [2] 0d 34 [2] 19 2f [2] 16 35 [2] 08 28 [2] 0a 29 [2] 11 2f [2] 0d 28 [2] 11 07 }

  condition:
    any of them
}