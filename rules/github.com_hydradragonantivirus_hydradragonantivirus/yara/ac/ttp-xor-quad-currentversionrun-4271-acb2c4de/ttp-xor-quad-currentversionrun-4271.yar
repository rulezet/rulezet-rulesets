rule TTP_XOR_QUAD_CurrentVersionRun_4271 {
  strings:
    $key_4271 = { 11 1e [2] 35 10 [2] 1e 3c [2] 30 1e [2] 24 05 [2] 2b 1f [2] 35 02 [2] 37 03 [2] 2c 05 [2] 30 02 [2] 2c 2d }

  condition:
    any of them
}