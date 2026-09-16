rule TTP_XOR_QUAD_CurrentVersionRun_4160 {
  strings:
    $key_4160 = { 12 0f [2] 36 01 [2] 1d 2d [2] 33 0f [2] 27 14 [2] 28 0e [2] 36 13 [2] 34 12 [2] 2f 14 [2] 33 13 [2] 2f 3c }

  condition:
    any of them
}