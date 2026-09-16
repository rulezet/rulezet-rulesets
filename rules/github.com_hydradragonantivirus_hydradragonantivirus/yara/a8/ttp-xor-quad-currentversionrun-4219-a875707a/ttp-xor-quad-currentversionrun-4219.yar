rule TTP_XOR_QUAD_CurrentVersionRun_4219 {
  strings:
    $key_4219 = { 11 76 [2] 35 78 [2] 1e 54 [2] 30 76 [2] 24 6d [2] 2b 77 [2] 35 6a [2] 37 6b [2] 2c 6d [2] 30 6a [2] 2c 45 }

  condition:
    any of them
}