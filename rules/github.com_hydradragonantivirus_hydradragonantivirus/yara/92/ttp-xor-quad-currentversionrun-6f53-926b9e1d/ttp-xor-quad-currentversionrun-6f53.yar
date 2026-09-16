rule TTP_XOR_QUAD_CurrentVersionRun_6f53 {
  strings:
    $key_6f53 = { 3c 3c [2] 18 32 [2] 33 1e [2] 1d 3c [2] 09 27 [2] 06 3d [2] 18 20 [2] 1a 21 [2] 01 27 [2] 1d 20 [2] 01 0f }

  condition:
    any of them
}