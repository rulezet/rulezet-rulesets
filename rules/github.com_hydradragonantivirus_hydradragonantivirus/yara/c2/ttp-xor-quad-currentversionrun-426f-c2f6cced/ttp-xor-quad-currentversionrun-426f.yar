rule TTP_XOR_QUAD_CurrentVersionRun_426f {
  strings:
    $key_426f = { 11 00 [2] 35 0e [2] 1e 22 [2] 30 00 [2] 24 1b [2] 2b 01 [2] 35 1c [2] 37 1d [2] 2c 1b [2] 30 1c [2] 2c 33 }

  condition:
    any of them
}