rule TTP_XOR_QUAD_CurrentVersionRun_2760 {
  strings:
    $key_2760 = { 74 0f [2] 50 01 [2] 7b 2d [2] 55 0f [2] 41 14 [2] 4e 0e [2] 50 13 [2] 52 12 [2] 49 14 [2] 55 13 [2] 49 3c }

  condition:
    any of them
}