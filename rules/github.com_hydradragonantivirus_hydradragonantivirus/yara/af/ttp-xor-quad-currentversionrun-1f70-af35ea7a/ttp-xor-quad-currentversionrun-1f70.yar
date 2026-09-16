rule TTP_XOR_QUAD_CurrentVersionRun_1f70 {
  strings:
    $key_1f70 = { 4c 1f [2] 68 11 [2] 43 3d [2] 6d 1f [2] 79 04 [2] 76 1e [2] 68 03 [2] 6a 02 [2] 71 04 [2] 6d 03 [2] 71 2c }

  condition:
    any of them
}