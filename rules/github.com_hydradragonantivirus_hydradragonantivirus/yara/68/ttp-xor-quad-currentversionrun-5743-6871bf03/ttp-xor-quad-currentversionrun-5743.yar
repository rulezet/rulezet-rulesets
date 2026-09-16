rule TTP_XOR_QUAD_CurrentVersionRun_5743 {
  strings:
    $key_5743 = { 04 2c [2] 20 22 [2] 0b 0e [2] 25 2c [2] 31 37 [2] 3e 2d [2] 20 30 [2] 22 31 [2] 39 37 [2] 25 30 [2] 39 1f }

  condition:
    any of them
}