rule TTP_XOR_QUAD_CurrentVersionRun_7353 {
  strings:
    $key_7353 = { 20 3c [2] 04 32 [2] 2f 1e [2] 01 3c [2] 15 27 [2] 1a 3d [2] 04 20 [2] 06 21 [2] 1d 27 [2] 01 20 [2] 1d 0f }

  condition:
    any of them
}