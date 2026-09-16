rule TTP_XOR_QUAD_CurrentVersionRun_0170 {
  strings:
    $key_0170 = { 52 1f [2] 76 11 [2] 5d 3d [2] 73 1f [2] 67 04 [2] 68 1e [2] 76 03 [2] 74 02 [2] 6f 04 [2] 73 03 [2] 6f 2c }

  condition:
    any of them
}