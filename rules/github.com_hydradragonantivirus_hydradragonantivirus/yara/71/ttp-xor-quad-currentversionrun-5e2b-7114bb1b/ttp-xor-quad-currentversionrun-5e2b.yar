rule TTP_XOR_QUAD_CurrentVersionRun_5e2b {
  strings:
    $key_5e2b = { 0d 44 [2] 29 4a [2] 02 66 [2] 2c 44 [2] 38 5f [2] 37 45 [2] 29 58 [2] 2b 59 [2] 30 5f [2] 2c 58 [2] 30 77 }

  condition:
    any of them
}