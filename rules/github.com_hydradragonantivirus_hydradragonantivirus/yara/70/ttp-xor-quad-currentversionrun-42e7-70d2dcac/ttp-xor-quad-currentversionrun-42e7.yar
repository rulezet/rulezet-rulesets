rule TTP_XOR_QUAD_CurrentVersionRun_42e7 {
  strings:
    $key_42e7 = { 11 88 [2] 35 86 [2] 1e aa [2] 30 88 [2] 24 93 [2] 2b 89 [2] 35 94 [2] 37 95 [2] 2c 93 [2] 30 94 [2] 2c bb }

  condition:
    any of them
}