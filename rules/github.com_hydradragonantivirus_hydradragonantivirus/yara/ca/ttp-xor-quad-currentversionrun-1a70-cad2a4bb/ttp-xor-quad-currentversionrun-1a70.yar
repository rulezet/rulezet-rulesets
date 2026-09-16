rule TTP_XOR_QUAD_CurrentVersionRun_1a70 {
  strings:
    $key_1a70 = { 49 1f [2] 6d 11 [2] 46 3d [2] 68 1f [2] 7c 04 [2] 73 1e [2] 6d 03 [2] 6f 02 [2] 74 04 [2] 68 03 [2] 74 2c }

  condition:
    any of them
}