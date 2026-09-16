rule TTP_XOR_QUAD_CurrentVersionRun_4443 {
  strings:
    $key_4443 = { 17 2c [2] 33 22 [2] 18 0e [2] 36 2c [2] 22 37 [2] 2d 2d [2] 33 30 [2] 31 31 [2] 2a 37 [2] 36 30 [2] 2a 1f }

  condition:
    any of them
}