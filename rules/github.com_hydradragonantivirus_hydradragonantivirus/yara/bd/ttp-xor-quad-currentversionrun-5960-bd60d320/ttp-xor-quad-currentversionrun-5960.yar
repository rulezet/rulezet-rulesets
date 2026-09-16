rule TTP_XOR_QUAD_CurrentVersionRun_5960 {
  strings:
    $key_5960 = { 0a 0f [2] 2e 01 [2] 05 2d [2] 2b 0f [2] 3f 14 [2] 30 0e [2] 2e 13 [2] 2c 12 [2] 37 14 [2] 2b 13 [2] 37 3c }

  condition:
    any of them
}