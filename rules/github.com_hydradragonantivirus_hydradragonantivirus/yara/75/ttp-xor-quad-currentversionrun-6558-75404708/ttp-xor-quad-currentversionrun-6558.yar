rule TTP_XOR_QUAD_CurrentVersionRun_6558 {
  strings:
    $key_6558 = { 36 37 [2] 12 39 [2] 39 15 [2] 17 37 [2] 03 2c [2] 0c 36 [2] 12 2b [2] 10 2a [2] 0b 2c [2] 17 2b [2] 0b 04 }

  condition:
    any of them
}