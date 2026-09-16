rule TTP_XOR_QUAD_CurrentVersionRun_1443 {
  strings:
    $key_1443 = { 47 2c [2] 63 22 [2] 48 0e [2] 66 2c [2] 72 37 [2] 7d 2d [2] 63 30 [2] 61 31 [2] 7a 37 [2] 66 30 [2] 7a 1f }

  condition:
    any of them
}