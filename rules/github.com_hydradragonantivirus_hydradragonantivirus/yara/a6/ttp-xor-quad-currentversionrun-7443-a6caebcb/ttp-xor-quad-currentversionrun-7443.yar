rule TTP_XOR_QUAD_CurrentVersionRun_7443 {
  strings:
    $key_7443 = { 27 2c [2] 03 22 [2] 28 0e [2] 06 2c [2] 12 37 [2] 1d 2d [2] 03 30 [2] 01 31 [2] 1a 37 [2] 06 30 [2] 1a 1f }

  condition:
    any of them
}