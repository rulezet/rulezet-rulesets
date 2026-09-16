rule TTP_XOR_QUAD_CurrentVersionRun_6570 {
  strings:
    $key_6570 = { 36 1f [2] 12 11 [2] 39 3d [2] 17 1f [2] 03 04 [2] 0c 1e [2] 12 03 [2] 10 02 [2] 0b 04 [2] 17 03 [2] 0b 2c }

  condition:
    any of them
}