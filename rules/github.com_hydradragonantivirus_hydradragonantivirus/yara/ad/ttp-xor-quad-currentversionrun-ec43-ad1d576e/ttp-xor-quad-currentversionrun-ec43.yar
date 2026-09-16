rule TTP_XOR_QUAD_CurrentVersionRun_ec43 {
  strings:
    $key_ec43 = { bf 2c [2] 9b 22 [2] b0 0e [2] 9e 2c [2] 8a 37 [2] 85 2d [2] 9b 30 [2] 99 31 [2] 82 37 [2] 9e 30 [2] 82 1f }

  condition:
    any of them
}