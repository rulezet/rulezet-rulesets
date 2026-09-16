rule TTP_XOR_QUAD_CurrentVersionRun_5558 {
  strings:
    $key_5558 = { 06 37 [2] 22 39 [2] 09 15 [2] 27 37 [2] 33 2c [2] 3c 36 [2] 22 2b [2] 20 2a [2] 3b 2c [2] 27 2b [2] 3b 04 }

  condition:
    any of them
}