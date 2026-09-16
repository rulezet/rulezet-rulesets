rule TTP_XOR_QUAD_CurrentVersionRun_f860 {
  strings:
    $key_f860 = { ab 0f [2] 8f 01 [2] a4 2d [2] 8a 0f [2] 9e 14 [2] 91 0e [2] 8f 13 [2] 8d 12 [2] 96 14 [2] 8a 13 [2] 96 3c }

  condition:
    any of them
}