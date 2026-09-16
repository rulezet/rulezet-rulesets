rule TTP_XOR_QUAD_CurrentVersionRun_3443 {
  strings:
    $key_3443 = { 67 2c [2] 43 22 [2] 68 0e [2] 46 2c [2] 52 37 [2] 5d 2d [2] 43 30 [2] 41 31 [2] 5a 37 [2] 46 30 [2] 5a 1f }

  condition:
    any of them
}