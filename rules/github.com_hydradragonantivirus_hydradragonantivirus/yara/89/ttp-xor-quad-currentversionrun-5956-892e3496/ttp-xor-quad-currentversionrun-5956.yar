rule TTP_XOR_QUAD_CurrentVersionRun_5956 {
  strings:
    $key_5956 = { 0a 39 [2] 2e 37 [2] 05 1b [2] 2b 39 [2] 3f 22 [2] 30 38 [2] 2e 25 [2] 2c 24 [2] 37 22 [2] 2b 25 [2] 37 0a }

  condition:
    any of them
}