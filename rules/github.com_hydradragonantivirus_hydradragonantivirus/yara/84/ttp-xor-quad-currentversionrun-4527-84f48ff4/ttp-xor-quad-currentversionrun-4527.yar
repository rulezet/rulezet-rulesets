rule TTP_XOR_QUAD_CurrentVersionRun_4527 {
  strings:
    $key_4527 = { 16 48 [2] 32 46 [2] 19 6a [2] 37 48 [2] 23 53 [2] 2c 49 [2] 32 54 [2] 30 55 [2] 2b 53 [2] 37 54 [2] 2b 7b }

  condition:
    any of them
}