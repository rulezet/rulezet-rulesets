rule TTP_XOR_QUAD_CurrentVersionRun_425b {
  strings:
    $key_425b = { 11 34 [2] 35 3a [2] 1e 16 [2] 30 34 [2] 24 2f [2] 2b 35 [2] 35 28 [2] 37 29 [2] 2c 2f [2] 30 28 [2] 2c 07 }

  condition:
    any of them
}