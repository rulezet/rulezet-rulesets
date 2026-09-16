rule TTP_XOR_QUAD_CurrentVersionRun_1853 {
  strings:
    $key_1853 = { 4b 3c [2] 6f 32 [2] 44 1e [2] 6a 3c [2] 7e 27 [2] 71 3d [2] 6f 20 [2] 6d 21 [2] 76 27 [2] 6a 20 [2] 76 0f }

  condition:
    any of them
}