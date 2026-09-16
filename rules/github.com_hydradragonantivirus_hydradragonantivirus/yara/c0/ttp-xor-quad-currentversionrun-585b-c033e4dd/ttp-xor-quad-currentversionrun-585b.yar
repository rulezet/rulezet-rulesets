rule TTP_XOR_QUAD_CurrentVersionRun_585b {
  strings:
    $key_585b = { 0b 34 [2] 2f 3a [2] 04 16 [2] 2a 34 [2] 3e 2f [2] 31 35 [2] 2f 28 [2] 2d 29 [2] 36 2f [2] 2a 28 [2] 36 07 }

  condition:
    any of them
}