rule TTP_XOR_QUAD_CurrentVersionRun_5957 {
  strings:
    $key_5957 = { 0a 38 [2] 2e 36 [2] 05 1a [2] 2b 38 [2] 3f 23 [2] 30 39 [2] 2e 24 [2] 2c 25 [2] 37 23 [2] 2b 24 [2] 37 0b }

  condition:
    any of them
}