rule TTP_XOR_QUAD_CurrentVersionRun_7453 {
  strings:
    $key_7453 = { 27 3c [2] 03 32 [2] 28 1e [2] 06 3c [2] 12 27 [2] 1d 3d [2] 03 20 [2] 01 21 [2] 1a 27 [2] 06 20 [2] 1a 0f }

  condition:
    any of them
}