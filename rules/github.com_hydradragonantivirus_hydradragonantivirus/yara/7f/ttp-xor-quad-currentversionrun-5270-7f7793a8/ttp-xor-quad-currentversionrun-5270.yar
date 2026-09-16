rule TTP_XOR_QUAD_CurrentVersionRun_5270 {
  strings:
    $key_5270 = { 01 1f [2] 25 11 [2] 0e 3d [2] 20 1f [2] 34 04 [2] 3b 1e [2] 25 03 [2] 27 02 [2] 3c 04 [2] 20 03 [2] 3c 2c }

  condition:
    any of them
}