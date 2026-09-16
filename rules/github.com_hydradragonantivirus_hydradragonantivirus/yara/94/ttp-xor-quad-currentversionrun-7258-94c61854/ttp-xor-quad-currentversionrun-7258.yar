rule TTP_XOR_QUAD_CurrentVersionRun_7258 {
  strings:
    $key_7258 = { 21 37 [2] 05 39 [2] 2e 15 [2] 00 37 [2] 14 2c [2] 1b 36 [2] 05 2b [2] 07 2a [2] 1c 2c [2] 00 2b [2] 1c 04 }

  condition:
    any of them
}