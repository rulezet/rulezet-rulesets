rule TTP_XOR_QUAD_CurrentVersionRun_cf43 {
  strings:
    $key_cf43 = { 9c 2c [2] b8 22 [2] 93 0e [2] bd 2c [2] a9 37 [2] a6 2d [2] b8 30 [2] ba 31 [2] a1 37 [2] bd 30 [2] a1 1f }

  condition:
    any of them
}