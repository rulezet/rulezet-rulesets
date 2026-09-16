rule TTP_XOR_QUAD_CurrentVersionRun_0153 {
  strings:
    $key_0153 = { 52 3c [2] 76 32 [2] 5d 1e [2] 73 3c [2] 67 27 [2] 68 3d [2] 76 20 [2] 74 21 [2] 6f 27 [2] 73 20 [2] 6f 0f }

  condition:
    any of them
}