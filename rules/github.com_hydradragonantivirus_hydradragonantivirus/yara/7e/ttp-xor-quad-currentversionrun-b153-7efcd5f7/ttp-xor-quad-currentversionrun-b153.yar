rule TTP_XOR_QUAD_CurrentVersionRun_b153 {
  strings:
    $key_b153 = { e2 3c [2] c6 32 [2] ed 1e [2] c3 3c [2] d7 27 [2] d8 3d [2] c6 20 [2] c4 21 [2] df 27 [2] c3 20 [2] df 0f }

  condition:
    any of them
}