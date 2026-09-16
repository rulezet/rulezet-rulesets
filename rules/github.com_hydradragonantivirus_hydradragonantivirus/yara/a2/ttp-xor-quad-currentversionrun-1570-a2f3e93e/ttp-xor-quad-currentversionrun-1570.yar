rule TTP_XOR_QUAD_CurrentVersionRun_1570 {
  strings:
    $key_1570 = { 46 1f [2] 62 11 [2] 49 3d [2] 67 1f [2] 73 04 [2] 7c 1e [2] 62 03 [2] 60 02 [2] 7b 04 [2] 67 03 [2] 7b 2c }

  condition:
    any of them
}