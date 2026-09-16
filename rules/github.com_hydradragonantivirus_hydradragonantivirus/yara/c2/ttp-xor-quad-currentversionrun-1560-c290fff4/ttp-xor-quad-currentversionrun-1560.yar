rule TTP_XOR_QUAD_CurrentVersionRun_1560 {
  strings:
    $key_1560 = { 46 0f [2] 62 01 [2] 49 2d [2] 67 0f [2] 73 14 [2] 7c 0e [2] 62 13 [2] 60 12 [2] 7b 14 [2] 67 13 [2] 7b 3c }

  condition:
    any of them
}