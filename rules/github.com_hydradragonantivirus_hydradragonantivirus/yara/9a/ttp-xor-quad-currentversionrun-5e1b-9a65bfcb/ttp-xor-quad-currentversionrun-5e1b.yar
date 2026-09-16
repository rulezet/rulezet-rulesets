rule TTP_XOR_QUAD_CurrentVersionRun_5e1b {
  strings:
    $key_5e1b = { 0d 74 [2] 29 7a [2] 02 56 [2] 2c 74 [2] 38 6f [2] 37 75 [2] 29 68 [2] 2b 69 [2] 30 6f [2] 2c 68 [2] 30 47 }

  condition:
    any of them
}