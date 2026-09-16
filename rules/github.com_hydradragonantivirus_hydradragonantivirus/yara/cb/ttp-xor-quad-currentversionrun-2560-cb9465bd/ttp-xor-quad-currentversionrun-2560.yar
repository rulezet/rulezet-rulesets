rule TTP_XOR_QUAD_CurrentVersionRun_2560 {
  strings:
    $key_2560 = { 76 0f [2] 52 01 [2] 79 2d [2] 57 0f [2] 43 14 [2] 4c 0e [2] 52 13 [2] 50 12 [2] 4b 14 [2] 57 13 [2] 4b 3c }

  condition:
    any of them
}