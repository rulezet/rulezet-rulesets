rule TTP_XOR_QUAD_CurrentVersionRun_3370 {
  strings:
    $key_3370 = { 60 1f [2] 44 11 [2] 6f 3d [2] 41 1f [2] 55 04 [2] 5a 1e [2] 44 03 [2] 46 02 [2] 5d 04 [2] 41 03 [2] 5d 2c }

  condition:
    any of them
}