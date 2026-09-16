rule TTP_XOR_QUAD_CurrentVersionRun_3a53 {
  strings:
    $key_3a53 = { 69 3c [2] 4d 32 [2] 66 1e [2] 48 3c [2] 5c 27 [2] 53 3d [2] 4d 20 [2] 4f 21 [2] 54 27 [2] 48 20 [2] 54 0f }

  condition:
    any of them
}