rule TTP_XOR_QUAD_CurrentVersionRun_5470 {
  strings:
    $key_5470 = { 07 1f [2] 23 11 [2] 08 3d [2] 26 1f [2] 32 04 [2] 3d 1e [2] 23 03 [2] 21 02 [2] 3a 04 [2] 26 03 [2] 3a 2c }

  condition:
    any of them
}