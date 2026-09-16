rule TTP_XOR_QUAD_CurrentVersionRun_0853 {
  strings:
    $key_0853 = { 5b 3c [2] 7f 32 [2] 54 1e [2] 7a 3c [2] 6e 27 [2] 61 3d [2] 7f 20 [2] 7d 21 [2] 66 27 [2] 7a 20 [2] 66 0f }

  condition:
    any of them
}