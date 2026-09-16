rule TTP_XOR_QUAD_CurrentVersionRun_5370 {
  strings:
    $key_5370 = { 00 1f [2] 24 11 [2] 0f 3d [2] 21 1f [2] 35 04 [2] 3a 1e [2] 24 03 [2] 26 02 [2] 3d 04 [2] 21 03 [2] 3d 2c }

  condition:
    any of them
}