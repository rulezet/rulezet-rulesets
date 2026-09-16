rule TTP_XOR_QUAD_CurrentVersionRun_7064 {
  strings:
    $key_7064 = { 23 0b [2] 07 05 [2] 2c 29 [2] 02 0b [2] 16 10 [2] 19 0a [2] 07 17 [2] 05 16 [2] 1e 10 [2] 02 17 [2] 1e 38 }

  condition:
    any of them
}