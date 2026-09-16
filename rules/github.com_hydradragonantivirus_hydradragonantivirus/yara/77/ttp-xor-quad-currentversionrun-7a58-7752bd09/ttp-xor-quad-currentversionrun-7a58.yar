rule TTP_XOR_QUAD_CurrentVersionRun_7a58 {
  strings:
    $key_7a58 = { 29 37 [2] 0d 39 [2] 26 15 [2] 08 37 [2] 1c 2c [2] 13 36 [2] 0d 2b [2] 0f 2a [2] 14 2c [2] 08 2b [2] 14 04 }

  condition:
    any of them
}