rule TTP_XOR_QUAD_CurrentVersionRun_4758 {
  strings:
    $key_4758 = { 14 37 [2] 30 39 [2] 1b 15 [2] 35 37 [2] 21 2c [2] 2e 36 [2] 30 2b [2] 32 2a [2] 29 2c [2] 35 2b [2] 29 04 }

  condition:
    any of them
}