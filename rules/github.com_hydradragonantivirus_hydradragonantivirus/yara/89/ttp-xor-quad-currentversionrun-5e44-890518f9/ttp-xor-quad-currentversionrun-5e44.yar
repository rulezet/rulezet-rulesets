rule TTP_XOR_QUAD_CurrentVersionRun_5e44 {
  strings:
    $key_5e44 = { 0d 2b [2] 29 25 [2] 02 09 [2] 2c 2b [2] 38 30 [2] 37 2a [2] 29 37 [2] 2b 36 [2] 30 30 [2] 2c 37 [2] 30 18 }

  condition:
    any of them
}