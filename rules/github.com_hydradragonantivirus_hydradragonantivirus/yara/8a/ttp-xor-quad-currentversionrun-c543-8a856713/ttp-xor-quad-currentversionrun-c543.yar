rule TTP_XOR_QUAD_CurrentVersionRun_c543 {
  strings:
    $key_c543 = { 96 2c [2] b2 22 [2] 99 0e [2] b7 2c [2] a3 37 [2] ac 2d [2] b2 30 [2] b0 31 [2] ab 37 [2] b7 30 [2] ab 1f }

  condition:
    any of them
}