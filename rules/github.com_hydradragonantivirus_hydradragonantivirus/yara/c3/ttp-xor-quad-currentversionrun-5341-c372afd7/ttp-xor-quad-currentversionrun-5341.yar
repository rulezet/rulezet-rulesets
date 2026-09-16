rule TTP_XOR_QUAD_CurrentVersionRun_5341 {
  strings:
    $key_5341 = { 00 2e [2] 24 20 [2] 0f 0c [2] 21 2e [2] 35 35 [2] 3a 2f [2] 24 32 [2] 26 33 [2] 3d 35 [2] 21 32 [2] 3d 1d }

  condition:
    any of them
}