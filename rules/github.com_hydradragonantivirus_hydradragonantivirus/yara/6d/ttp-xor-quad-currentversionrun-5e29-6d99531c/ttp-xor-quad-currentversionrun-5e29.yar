rule TTP_XOR_QUAD_CurrentVersionRun_5e29 {
  strings:
    $key_5e29 = { 0d 46 [2] 29 48 [2] 02 64 [2] 2c 46 [2] 38 5d [2] 37 47 [2] 29 5a [2] 2b 5b [2] 30 5d [2] 2c 5a [2] 30 75 }

  condition:
    any of them
}