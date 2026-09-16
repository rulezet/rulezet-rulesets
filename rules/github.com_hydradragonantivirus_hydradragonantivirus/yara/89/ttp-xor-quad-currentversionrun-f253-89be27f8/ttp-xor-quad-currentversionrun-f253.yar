rule TTP_XOR_QUAD_CurrentVersionRun_f253 {
  strings:
    $key_f253 = { a1 3c [2] 85 32 [2] ae 1e [2] 80 3c [2] 94 27 [2] 9b 3d [2] 85 20 [2] 87 21 [2] 9c 27 [2] 80 20 [2] 9c 0f }

  condition:
    any of them
}