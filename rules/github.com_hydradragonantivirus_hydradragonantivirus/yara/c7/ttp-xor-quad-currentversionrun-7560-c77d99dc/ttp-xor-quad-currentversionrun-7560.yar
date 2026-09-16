rule TTP_XOR_QUAD_CurrentVersionRun_7560 {
  strings:
    $key_7560 = { 26 0f [2] 02 01 [2] 29 2d [2] 07 0f [2] 13 14 [2] 1c 0e [2] 02 13 [2] 00 12 [2] 1b 14 [2] 07 13 [2] 1b 3c }

  condition:
    any of them
}