rule TTP_XOR_QUAD_CurrentVersionRun_2853 {
  strings:
    $key_2853 = { 7b 3c [2] 5f 32 [2] 74 1e [2] 5a 3c [2] 4e 27 [2] 41 3d [2] 5f 20 [2] 5d 21 [2] 46 27 [2] 5a 20 [2] 46 0f }

  condition:
    any of them
}