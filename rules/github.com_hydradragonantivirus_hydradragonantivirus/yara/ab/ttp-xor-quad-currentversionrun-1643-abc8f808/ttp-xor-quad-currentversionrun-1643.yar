rule TTP_XOR_QUAD_CurrentVersionRun_1643 {
  strings:
    $key_1643 = { 45 2c [2] 61 22 [2] 4a 0e [2] 64 2c [2] 70 37 [2] 7f 2d [2] 61 30 [2] 63 31 [2] 78 37 [2] 64 30 [2] 78 1f }

  condition:
    any of them
}