rule TTP_XOR_QUAD_CurrentVersionRun_426b {
  strings:
    $key_426b = { 11 04 [2] 35 0a [2] 1e 26 [2] 30 04 [2] 24 1f [2] 2b 05 [2] 35 18 [2] 37 19 [2] 2c 1f [2] 30 18 [2] 2c 37 }

  condition:
    any of them
}