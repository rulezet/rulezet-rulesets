rule TTP_XOR_QUAD_CurrentVersionRun_bb43 {
  strings:
    $key_bb43 = { e8 2c [2] cc 22 [2] e7 0e [2] c9 2c [2] dd 37 [2] d2 2d [2] cc 30 [2] ce 31 [2] d5 37 [2] c9 30 [2] d5 1f }

  condition:
    any of them
}