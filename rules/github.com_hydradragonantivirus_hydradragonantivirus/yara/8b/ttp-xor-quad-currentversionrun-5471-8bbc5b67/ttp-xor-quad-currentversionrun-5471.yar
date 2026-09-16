rule TTP_XOR_QUAD_CurrentVersionRun_5471 {
  strings:
    $key_5471 = { 07 1e [2] 23 10 [2] 08 3c [2] 26 1e [2] 32 05 [2] 3d 1f [2] 23 02 [2] 21 03 [2] 3a 05 [2] 26 02 [2] 3a 2d }

  condition:
    any of them
}