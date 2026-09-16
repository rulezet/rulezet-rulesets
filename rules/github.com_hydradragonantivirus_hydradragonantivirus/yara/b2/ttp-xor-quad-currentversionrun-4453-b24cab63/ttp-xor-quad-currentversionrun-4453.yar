rule TTP_XOR_QUAD_CurrentVersionRun_4453 {
  strings:
    $key_4453 = { 17 3c [2] 33 32 [2] 18 1e [2] 36 3c [2] 22 27 [2] 2d 3d [2] 33 20 [2] 31 21 [2] 2a 27 [2] 36 20 [2] 2a 0f }

  condition:
    any of them
}