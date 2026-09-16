rule TTP_XOR_QUAD_CurrentVersionRun_7970 {
  strings:
    $key_7970 = { 2a 1f [2] 0e 11 [2] 25 3d [2] 0b 1f [2] 1f 04 [2] 10 1e [2] 0e 03 [2] 0c 02 [2] 17 04 [2] 0b 03 [2] 17 2c }

  condition:
    any of them
}