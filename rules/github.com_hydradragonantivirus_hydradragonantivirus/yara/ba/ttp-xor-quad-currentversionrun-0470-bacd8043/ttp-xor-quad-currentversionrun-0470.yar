rule TTP_XOR_QUAD_CurrentVersionRun_0470 {
  strings:
    $key_0470 = { 57 1f [2] 73 11 [2] 58 3d [2] 76 1f [2] 62 04 [2] 6d 1e [2] 73 03 [2] 71 02 [2] 6a 04 [2] 76 03 [2] 6a 2c }

  condition:
    any of them
}