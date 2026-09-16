rule TTP_XOR_QUAD_CurrentVersionRun_4a53 {
  strings:
    $key_4a53 = { 19 3c [2] 3d 32 [2] 16 1e [2] 38 3c [2] 2c 27 [2] 23 3d [2] 3d 20 [2] 3f 21 [2] 24 27 [2] 38 20 [2] 24 0f }

  condition:
    any of them
}