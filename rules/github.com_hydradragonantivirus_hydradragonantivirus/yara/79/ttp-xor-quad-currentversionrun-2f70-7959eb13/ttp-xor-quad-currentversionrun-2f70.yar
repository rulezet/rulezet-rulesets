rule TTP_XOR_QUAD_CurrentVersionRun_2f70 {
  strings:
    $key_2f70 = { 7c 1f [2] 58 11 [2] 73 3d [2] 5d 1f [2] 49 04 [2] 46 1e [2] 58 03 [2] 5a 02 [2] 41 04 [2] 5d 03 [2] 41 2c }

  condition:
    any of them
}