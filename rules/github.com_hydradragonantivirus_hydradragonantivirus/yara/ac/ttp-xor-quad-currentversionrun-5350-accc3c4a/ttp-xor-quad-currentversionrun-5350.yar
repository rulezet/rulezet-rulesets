rule TTP_XOR_QUAD_CurrentVersionRun_5350 {
  strings:
    $key_5350 = { 00 3f [2] 24 31 [2] 0f 1d [2] 21 3f [2] 35 24 [2] 3a 3e [2] 24 23 [2] 26 22 [2] 3d 24 [2] 21 23 [2] 3d 0c }

  condition:
    any of them
}