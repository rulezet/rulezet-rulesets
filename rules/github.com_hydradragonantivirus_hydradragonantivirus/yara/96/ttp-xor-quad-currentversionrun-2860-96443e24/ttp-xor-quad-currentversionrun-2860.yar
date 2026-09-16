rule TTP_XOR_QUAD_CurrentVersionRun_2860 {
  strings:
    $key_2860 = { 7b 0f [2] 5f 01 [2] 74 2d [2] 5a 0f [2] 4e 14 [2] 41 0e [2] 5f 13 [2] 5d 12 [2] 46 14 [2] 5a 13 [2] 46 3c }

  condition:
    any of them
}