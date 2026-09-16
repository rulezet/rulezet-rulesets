rule TTP_XOR_QUAD_CurrentVersionRun_4224 {
  strings:
    $key_4224 = { 11 4b [2] 35 45 [2] 1e 69 [2] 30 4b [2] 24 50 [2] 2b 4a [2] 35 57 [2] 37 56 [2] 2c 50 [2] 30 57 [2] 2c 78 }

  condition:
    any of them
}