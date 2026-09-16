rule TTP_XOR_QUAD_CurrentVersionRun_6353 {
  strings:
    $key_6353 = { 30 3c [2] 14 32 [2] 3f 1e [2] 11 3c [2] 05 27 [2] 0a 3d [2] 14 20 [2] 16 21 [2] 0d 27 [2] 11 20 [2] 0d 0f }

  condition:
    any of them
}