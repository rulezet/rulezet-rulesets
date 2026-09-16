rule TTP_XOR_QUAD_CurrentVersionRun_6870 {
  strings:
    $key_6870 = { 3b 1f [2] 1f 11 [2] 34 3d [2] 1a 1f [2] 0e 04 [2] 01 1e [2] 1f 03 [2] 1d 02 [2] 06 04 [2] 1a 03 [2] 06 2c }

  condition:
    any of them
}