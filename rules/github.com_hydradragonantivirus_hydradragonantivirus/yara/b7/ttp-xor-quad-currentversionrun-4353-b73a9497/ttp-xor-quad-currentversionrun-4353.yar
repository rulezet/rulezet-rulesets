rule TTP_XOR_QUAD_CurrentVersionRun_4353 {
  strings:
    $key_4353 = { 10 3c [2] 34 32 [2] 1f 1e [2] 31 3c [2] 25 27 [2] 2a 3d [2] 34 20 [2] 36 21 [2] 2d 27 [2] 31 20 [2] 2d 0f }

  condition:
    any of them
}