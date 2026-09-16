rule TTP_XOR_QUAD_CurrentVersionRun_7f54 {
  strings:
    $key_7f54 = { 2c 3b [2] 08 35 [2] 23 19 [2] 0d 3b [2] 19 20 [2] 16 3a [2] 08 27 [2] 0a 26 [2] 11 20 [2] 0d 27 [2] 11 08 }

  condition:
    any of them
}