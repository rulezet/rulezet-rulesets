rule TTP_XOR_QUAD_CurrentVersionRun_e443 {
  strings:
    $key_e443 = { b7 2c [2] 93 22 [2] b8 0e [2] 96 2c [2] 82 37 [2] 8d 2d [2] 93 30 [2] 91 31 [2] 8a 37 [2] 96 30 [2] 8a 1f }

  condition:
    any of them
}