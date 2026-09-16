rule TTP_XOR_QUAD_CurrentVersionRun_5371 {
  strings:
    $key_5371 = { 00 1e [2] 24 10 [2] 0f 3c [2] 21 1e [2] 35 05 [2] 3a 1f [2] 24 02 [2] 26 03 [2] 3d 05 [2] 21 02 [2] 3d 2d }

  condition:
    any of them
}