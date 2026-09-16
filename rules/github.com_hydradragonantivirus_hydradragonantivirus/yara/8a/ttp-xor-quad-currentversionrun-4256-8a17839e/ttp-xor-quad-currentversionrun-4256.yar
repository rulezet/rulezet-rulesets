rule TTP_XOR_QUAD_CurrentVersionRun_4256 {
  strings:
    $key_4256 = { 11 39 [2] 35 37 [2] 1e 1b [2] 30 39 [2] 24 22 [2] 2b 38 [2] 35 25 [2] 37 24 [2] 2c 22 [2] 30 25 [2] 2c 0a }

  condition:
    any of them
}