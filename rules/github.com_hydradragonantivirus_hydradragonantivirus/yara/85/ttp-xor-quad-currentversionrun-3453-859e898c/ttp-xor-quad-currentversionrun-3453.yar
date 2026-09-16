rule TTP_XOR_QUAD_CurrentVersionRun_3453 {
  strings:
    $key_3453 = { 67 3c [2] 43 32 [2] 68 1e [2] 46 3c [2] 52 27 [2] 5d 3d [2] 43 20 [2] 41 21 [2] 5a 27 [2] 46 20 [2] 5a 0f }

  condition:
    any of them
}