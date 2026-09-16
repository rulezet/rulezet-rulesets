rule TTP_XOR_QUAD_CurrentVersionRun_6070 {
  strings:
    $key_6070 = { 33 1f [2] 17 11 [2] 3c 3d [2] 12 1f [2] 06 04 [2] 09 1e [2] 17 03 [2] 15 02 [2] 0e 04 [2] 12 03 [2] 0e 2c }

  condition:
    any of them
}