rule TTP_XOR_QUAD_CurrentVersionRun_5853 {
  strings:
    $key_5853 = { 0b 3c [2] 2f 32 [2] 04 1e [2] 2a 3c [2] 3e 27 [2] 31 3d [2] 2f 20 [2] 2d 21 [2] 36 27 [2] 2a 20 [2] 36 0f }

  condition:
    any of them
}