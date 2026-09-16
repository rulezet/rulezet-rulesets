rule TTP_XOR_QUAD_CurrentVersionRun_5e54 {
  strings:
    $key_5e54 = { 0d 3b [2] 29 35 [2] 02 19 [2] 2c 3b [2] 38 20 [2] 37 3a [2] 29 27 [2] 2b 26 [2] 30 20 [2] 2c 27 [2] 30 08 }

  condition:
    any of them
}