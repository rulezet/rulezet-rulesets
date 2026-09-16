rule TTP_XOR_QUAD_CurrentVersionRun_6053 {
  strings:
    $key_6053 = { 33 3c [2] 17 32 [2] 3c 1e [2] 12 3c [2] 06 27 [2] 09 3d [2] 17 20 [2] 15 21 [2] 0e 27 [2] 12 20 [2] 0e 0f }

  condition:
    any of them
}