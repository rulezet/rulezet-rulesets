rule TTP_XOR_QUAD_CurrentVersionRun_6453 {
  strings:
    $key_6453 = { 37 3c [2] 13 32 [2] 38 1e [2] 16 3c [2] 02 27 [2] 0d 3d [2] 13 20 [2] 11 21 [2] 0a 27 [2] 16 20 [2] 0a 0f }

  condition:
    any of them
}