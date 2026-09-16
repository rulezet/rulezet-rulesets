rule TTP_XOR_QUAD_CurrentVersionRun_5463 {
  strings:
    $key_5463 = { 07 0c [2] 23 02 [2] 08 2e [2] 26 0c [2] 32 17 [2] 3d 0d [2] 23 10 [2] 21 11 [2] 3a 17 [2] 26 10 [2] 3a 3f }

  condition:
    any of them
}