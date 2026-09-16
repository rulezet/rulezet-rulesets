rule TTP_XOR_QUAD_CurrentVersionRun_5f70 {
  strings:
    $key_5f70 = { 0c 1f [2] 28 11 [2] 03 3d [2] 2d 1f [2] 39 04 [2] 36 1e [2] 28 03 [2] 2a 02 [2] 31 04 [2] 2d 03 [2] 31 2c }

  condition:
    any of them
}