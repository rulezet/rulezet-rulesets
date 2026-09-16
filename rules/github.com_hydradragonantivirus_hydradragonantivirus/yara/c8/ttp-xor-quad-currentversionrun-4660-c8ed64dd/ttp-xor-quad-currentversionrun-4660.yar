rule TTP_XOR_QUAD_CurrentVersionRun_4660 {
  strings:
    $key_4660 = { 15 0f [2] 31 01 [2] 1a 2d [2] 34 0f [2] 20 14 [2] 2f 0e [2] 31 13 [2] 33 12 [2] 28 14 [2] 34 13 [2] 28 3c }

  condition:
    any of them
}