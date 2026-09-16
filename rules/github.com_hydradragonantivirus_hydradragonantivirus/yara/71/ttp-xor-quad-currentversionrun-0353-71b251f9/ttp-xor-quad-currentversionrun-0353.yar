rule TTP_XOR_QUAD_CurrentVersionRun_0353 {
  strings:
    $key_0353 = { 50 3c [2] 74 32 [2] 5f 1e [2] 71 3c [2] 65 27 [2] 6a 3d [2] 74 20 [2] 76 21 [2] 6d 27 [2] 71 20 [2] 6d 0f }

  condition:
    any of them
}