rule TTP_XOR_QUAD_CurrentVersionRun_5e60 {
  strings:
    $key_5e60 = { 0d 0f [2] 29 01 [2] 02 2d [2] 2c 0f [2] 38 14 [2] 37 0e [2] 29 13 [2] 2b 12 [2] 30 14 [2] 2c 13 [2] 30 3c }

  condition:
    any of them
}