rule TTP_XOR_QUAD_CurrentVersionRun_3160 {
  strings:
    $key_3160 = { 62 0f [2] 46 01 [2] 6d 2d [2] 43 0f [2] 57 14 [2] 58 0e [2] 46 13 [2] 44 12 [2] 5f 14 [2] 43 13 [2] 5f 3c }

  condition:
    any of them
}