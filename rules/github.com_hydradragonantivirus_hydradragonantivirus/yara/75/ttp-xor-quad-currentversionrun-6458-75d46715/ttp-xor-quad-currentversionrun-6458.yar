rule TTP_XOR_QUAD_CurrentVersionRun_6458 {
  strings:
    $key_6458 = { 37 37 [2] 13 39 [2] 38 15 [2] 16 37 [2] 02 2c [2] 0d 36 [2] 13 2b [2] 11 2a [2] 0a 2c [2] 16 2b [2] 0a 04 }

  condition:
    any of them
}