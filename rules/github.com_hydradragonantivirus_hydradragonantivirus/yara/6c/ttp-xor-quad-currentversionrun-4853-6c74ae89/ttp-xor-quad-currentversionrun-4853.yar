rule TTP_XOR_QUAD_CurrentVersionRun_4853 {
  strings:
    $key_4853 = { 1b 3c [2] 3f 32 [2] 14 1e [2] 3a 3c [2] 2e 27 [2] 21 3d [2] 3f 20 [2] 3d 21 [2] 26 27 [2] 3a 20 [2] 26 0f }

  condition:
    any of them
}