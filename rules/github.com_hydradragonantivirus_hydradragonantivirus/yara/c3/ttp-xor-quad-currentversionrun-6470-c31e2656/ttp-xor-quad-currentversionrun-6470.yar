rule TTP_XOR_QUAD_CurrentVersionRun_6470 {
  strings:
    $key_6470 = { 37 1f [2] 13 11 [2] 38 3d [2] 16 1f [2] 02 04 [2] 0d 1e [2] 13 03 [2] 11 02 [2] 0a 04 [2] 16 03 [2] 0a 2c }

  condition:
    any of them
}