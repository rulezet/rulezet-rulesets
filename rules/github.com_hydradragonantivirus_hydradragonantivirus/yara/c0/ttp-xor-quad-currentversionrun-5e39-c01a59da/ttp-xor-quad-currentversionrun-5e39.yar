rule TTP_XOR_QUAD_CurrentVersionRun_5e39 {
  strings:
    $key_5e39 = { 0d 56 [2] 29 58 [2] 02 74 [2] 2c 56 [2] 38 4d [2] 37 57 [2] 29 4a [2] 2b 4b [2] 30 4d [2] 2c 4a [2] 30 65 }

  condition:
    any of them
}