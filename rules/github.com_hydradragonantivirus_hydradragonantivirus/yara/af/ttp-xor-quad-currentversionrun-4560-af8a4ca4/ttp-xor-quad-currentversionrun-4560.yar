rule TTP_XOR_QUAD_CurrentVersionRun_4560 {
  strings:
    $key_4560 = { 16 0f [2] 32 01 [2] 19 2d [2] 37 0f [2] 23 14 [2] 2c 0e [2] 32 13 [2] 30 12 [2] 2b 14 [2] 37 13 [2] 2b 3c }

  condition:
    any of them
}