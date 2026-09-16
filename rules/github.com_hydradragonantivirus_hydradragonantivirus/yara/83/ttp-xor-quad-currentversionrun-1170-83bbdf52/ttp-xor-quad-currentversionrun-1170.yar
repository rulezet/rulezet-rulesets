rule TTP_XOR_QUAD_CurrentVersionRun_1170 {
  strings:
    $key_1170 = { 42 1f [2] 66 11 [2] 4d 3d [2] 63 1f [2] 77 04 [2] 78 1e [2] 66 03 [2] 64 02 [2] 7f 04 [2] 63 03 [2] 7f 2c }

  condition:
    any of them
}