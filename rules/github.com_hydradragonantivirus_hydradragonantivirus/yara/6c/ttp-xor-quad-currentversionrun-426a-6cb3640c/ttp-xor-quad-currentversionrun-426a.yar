rule TTP_XOR_QUAD_CurrentVersionRun_426a {
  strings:
    $key_426a = { 11 05 [2] 35 0b [2] 1e 27 [2] 30 05 [2] 24 1e [2] 2b 04 [2] 35 19 [2] 37 18 [2] 2c 1e [2] 30 19 [2] 2c 36 }

  condition:
    any of them
}