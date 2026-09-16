rule TTP_XOR_QUAD_CurrentVersionRun_426e {
  strings:
    $key_426e = { 11 01 [2] 35 0f [2] 1e 23 [2] 30 01 [2] 24 1a [2] 2b 00 [2] 35 1d [2] 37 1c [2] 2c 1a [2] 30 1d [2] 2c 32 }

  condition:
    any of them
}