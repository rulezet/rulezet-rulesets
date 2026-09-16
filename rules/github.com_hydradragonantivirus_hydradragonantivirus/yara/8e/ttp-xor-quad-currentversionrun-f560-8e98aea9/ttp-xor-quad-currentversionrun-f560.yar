rule TTP_XOR_QUAD_CurrentVersionRun_f560 {
  strings:
    $key_f560 = { a6 0f [2] 82 01 [2] a9 2d [2] 87 0f [2] 93 14 [2] 9c 0e [2] 82 13 [2] 80 12 [2] 9b 14 [2] 87 13 [2] 9b 3c }

  condition:
    any of them
}