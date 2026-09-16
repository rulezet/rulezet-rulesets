rule TTP_XOR_QUAD_CurrentVersionRun_e853 {
  strings:
    $key_e853 = { bb 3c [2] 9f 32 [2] b4 1e [2] 9a 3c [2] 8e 27 [2] 81 3d [2] 9f 20 [2] 9d 21 [2] 86 27 [2] 9a 20 [2] 86 0f }

  condition:
    any of them
}