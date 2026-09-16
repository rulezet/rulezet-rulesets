rule TTP_XOR_QUAD_CurrentVersionRun_7f70 {
  strings:
    $key_7f70 = { 2c 1f [2] 08 11 [2] 23 3d [2] 0d 1f [2] 19 04 [2] 16 1e [2] 08 03 [2] 0a 02 [2] 11 04 [2] 0d 03 [2] 11 2c }

  condition:
    any of them
}