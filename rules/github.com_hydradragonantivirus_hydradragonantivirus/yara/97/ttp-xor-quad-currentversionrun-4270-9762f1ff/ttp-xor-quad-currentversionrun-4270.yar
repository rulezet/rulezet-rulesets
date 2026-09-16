rule TTP_XOR_QUAD_CurrentVersionRun_4270 {
  strings:
    $key_4270 = { 11 1f [2] 35 11 [2] 1e 3d [2] 30 1f [2] 24 04 [2] 2b 1e [2] 35 03 [2] 37 02 [2] 2c 04 [2] 30 03 [2] 2c 2c }

  condition:
    any of them
}