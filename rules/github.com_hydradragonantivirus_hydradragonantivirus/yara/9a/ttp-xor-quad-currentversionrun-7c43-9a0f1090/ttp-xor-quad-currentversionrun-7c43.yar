rule TTP_XOR_QUAD_CurrentVersionRun_7c43 {
  strings:
    $key_7c43 = { 2f 2c [2] 0b 22 [2] 20 0e [2] 0e 2c [2] 1a 37 [2] 15 2d [2] 0b 30 [2] 09 31 [2] 12 37 [2] 0e 30 [2] 12 1f }

  condition:
    any of them
}