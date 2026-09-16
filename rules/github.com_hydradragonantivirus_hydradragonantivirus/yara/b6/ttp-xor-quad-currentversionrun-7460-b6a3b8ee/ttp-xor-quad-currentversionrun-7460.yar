rule TTP_XOR_QUAD_CurrentVersionRun_7460 {
  strings:
    $key_7460 = { 27 0f [2] 03 01 [2] 28 2d [2] 06 0f [2] 12 14 [2] 1d 0e [2] 03 13 [2] 01 12 [2] 1a 14 [2] 06 13 [2] 1a 3c }

  condition:
    any of them
}