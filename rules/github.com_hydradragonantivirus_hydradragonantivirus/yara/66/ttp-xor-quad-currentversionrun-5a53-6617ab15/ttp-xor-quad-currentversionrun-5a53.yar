rule TTP_XOR_QUAD_CurrentVersionRun_5a53 {
  strings:
    $key_5a53 = { 09 3c [2] 2d 32 [2] 06 1e [2] 28 3c [2] 3c 27 [2] 33 3d [2] 2d 20 [2] 2f 21 [2] 34 27 [2] 28 20 [2] 34 0f }

  condition:
    any of them
}