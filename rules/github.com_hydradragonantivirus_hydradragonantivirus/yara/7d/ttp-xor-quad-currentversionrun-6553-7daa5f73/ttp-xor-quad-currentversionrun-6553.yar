rule TTP_XOR_QUAD_CurrentVersionRun_6553 {
  strings:
    $key_6553 = { 36 3c [2] 12 32 [2] 39 1e [2] 17 3c [2] 03 27 [2] 0c 3d [2] 12 20 [2] 10 21 [2] 0b 27 [2] 17 20 [2] 0b 0f }

  condition:
    any of them
}