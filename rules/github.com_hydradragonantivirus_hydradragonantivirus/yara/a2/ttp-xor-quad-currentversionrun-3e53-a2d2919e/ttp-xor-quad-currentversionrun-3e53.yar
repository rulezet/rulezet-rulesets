rule TTP_XOR_QUAD_CurrentVersionRun_3e53 {
  strings:
    $key_3e53 = { 6d 3c [2] 49 32 [2] 62 1e [2] 4c 3c [2] 58 27 [2] 57 3d [2] 49 20 [2] 4b 21 [2] 50 27 [2] 4c 20 [2] 50 0f }

  condition:
    any of them
}