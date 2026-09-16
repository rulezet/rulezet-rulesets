rule TTP_XOR_QUAD_CurrentVersionRun_4370 {
  strings:
    $key_4370 = { 10 1f [2] 34 11 [2] 1f 3d [2] 31 1f [2] 25 04 [2] 2a 1e [2] 34 03 [2] 36 02 [2] 2d 04 [2] 31 03 [2] 2d 2c }

  condition:
    any of them
}