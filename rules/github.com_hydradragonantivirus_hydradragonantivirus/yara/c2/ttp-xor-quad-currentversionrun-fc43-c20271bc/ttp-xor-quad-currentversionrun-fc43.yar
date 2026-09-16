rule TTP_XOR_QUAD_CurrentVersionRun_fc43 {
  strings:
    $key_fc43 = { af 2c [2] 8b 22 [2] a0 0e [2] 8e 2c [2] 9a 37 [2] 95 2d [2] 8b 30 [2] 89 31 [2] 92 37 [2] 8e 30 [2] 92 1f }

  condition:
    any of them
}