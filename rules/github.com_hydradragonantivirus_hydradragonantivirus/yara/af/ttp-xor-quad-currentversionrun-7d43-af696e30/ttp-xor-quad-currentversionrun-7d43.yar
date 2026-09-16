rule TTP_XOR_QUAD_CurrentVersionRun_7d43 {
  strings:
    $key_7d43 = { 2e 2c [2] 0a 22 [2] 21 0e [2] 0f 2c [2] 1b 37 [2] 14 2d [2] 0a 30 [2] 08 31 [2] 13 37 [2] 0f 30 [2] 13 1f }

  condition:
    any of them
}