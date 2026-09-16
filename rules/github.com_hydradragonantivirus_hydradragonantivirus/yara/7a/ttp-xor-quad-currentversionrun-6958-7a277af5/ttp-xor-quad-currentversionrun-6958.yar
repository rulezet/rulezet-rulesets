rule TTP_XOR_QUAD_CurrentVersionRun_6958 {
  strings:
    $key_6958 = { 3a 37 [2] 1e 39 [2] 35 15 [2] 1b 37 [2] 0f 2c [2] 00 36 [2] 1e 2b [2] 1c 2a [2] 07 2c [2] 1b 2b [2] 07 04 }

  condition:
    any of them
}