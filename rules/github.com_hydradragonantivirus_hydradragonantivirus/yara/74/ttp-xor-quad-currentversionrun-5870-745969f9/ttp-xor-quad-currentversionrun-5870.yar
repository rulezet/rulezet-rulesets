rule TTP_XOR_QUAD_CurrentVersionRun_5870 {
  strings:
    $key_5870 = { 0b 1f [2] 2f 11 [2] 04 3d [2] 2a 1f [2] 3e 04 [2] 31 1e [2] 2f 03 [2] 2d 02 [2] 36 04 [2] 2a 03 [2] 36 2c }

  condition:
    any of them
}