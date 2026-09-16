rule TTP_XOR_QUAD_CurrentVersionRun_426d {
  strings:
    $key_426d = { 11 02 [2] 35 0c [2] 1e 20 [2] 30 02 [2] 24 19 [2] 2b 03 [2] 35 1e [2] 37 1f [2] 2c 19 [2] 30 1e [2] 2c 31 }

  condition:
    any of them
}