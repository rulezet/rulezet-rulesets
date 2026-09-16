rule TTP_XOR_QUAD_CurrentVersionRun_5453 {
  strings:
    $key_5453 = { 07 3c [2] 23 32 [2] 08 1e [2] 26 3c [2] 32 27 [2] 3d 3d [2] 23 20 [2] 21 21 [2] 3a 27 [2] 26 20 [2] 3a 0f }

  condition:
    any of them
}