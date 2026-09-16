rule TTP_XOR_QUAD_CurrentVersionRun_e943 {
  strings:
    $key_e943 = { ba 2c [2] 9e 22 [2] b5 0e [2] 9b 2c [2] 8f 37 [2] 80 2d [2] 9e 30 [2] 9c 31 [2] 87 37 [2] 9b 30 [2] 87 1f }

  condition:
    any of them
}