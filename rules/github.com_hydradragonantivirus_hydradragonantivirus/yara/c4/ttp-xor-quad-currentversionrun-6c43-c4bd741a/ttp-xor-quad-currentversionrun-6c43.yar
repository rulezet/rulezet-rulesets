rule TTP_XOR_QUAD_CurrentVersionRun_6c43 {
  strings:
    $key_6c43 = { 3f 2c [2] 1b 22 [2] 30 0e [2] 1e 2c [2] 0a 37 [2] 05 2d [2] 1b 30 [2] 19 31 [2] 02 37 [2] 1e 30 [2] 02 1f }

  condition:
    any of them
}