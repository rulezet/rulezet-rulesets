rule TTP_XOR_QUAD_CurrentVersionRun_0f53 {
  strings:
    $key_0f53 = { 5c 3c [2] 78 32 [2] 53 1e [2] 7d 3c [2] 69 27 [2] 66 3d [2] 78 20 [2] 7a 21 [2] 61 27 [2] 7d 20 [2] 61 0f }

  condition:
    any of them
}