rule TTP_XOR_QUAD_CurrentVersionRun_7153 {
  strings:
    $key_7153 = { 22 3c [2] 06 32 [2] 2d 1e [2] 03 3c [2] 17 27 [2] 18 3d [2] 06 20 [2] 04 21 [2] 1f 27 [2] 03 20 [2] 1f 0f }

  condition:
    any of them
}