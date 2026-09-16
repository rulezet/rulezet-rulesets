rule TTP_XOR_QUAD_CurrentVersionRun_4234 {
  strings:
    $key_4234 = { 11 5b [2] 35 55 [2] 1e 79 [2] 30 5b [2] 24 40 [2] 2b 5a [2] 35 47 [2] 37 46 [2] 2c 40 [2] 30 47 [2] 2c 68 }

  condition:
    any of them
}