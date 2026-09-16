rule TTP_XOR_QUAD_CurrentVersionRun_7f78 {
  strings:
    $key_7f78 = { 2c 17 [2] 08 19 [2] 23 35 [2] 0d 17 [2] 19 0c [2] 16 16 [2] 08 0b [2] 0a 0a [2] 11 0c [2] 0d 0b [2] 11 24 }

  condition:
    any of them
}