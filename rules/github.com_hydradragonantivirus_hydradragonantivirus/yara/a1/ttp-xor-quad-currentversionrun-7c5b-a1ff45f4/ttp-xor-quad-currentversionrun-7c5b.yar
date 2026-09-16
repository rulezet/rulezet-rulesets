rule TTP_XOR_QUAD_CurrentVersionRun_7c5b {
  strings:
    $key_7c5b = { 2f 34 [2] 0b 3a [2] 20 16 [2] 0e 34 [2] 1a 2f [2] 15 35 [2] 0b 28 [2] 09 29 [2] 12 2f [2] 0e 28 [2] 12 07 }

  condition:
    any of them
}