rule TTP_XOR_QUAD_CurrentVersionRun_1c60 {
  strings:
    $key_1c60 = { 4f 0f [2] 6b 01 [2] 40 2d [2] 6e 0f [2] 7a 14 [2] 75 0e [2] 6b 13 [2] 69 12 [2] 72 14 [2] 6e 13 [2] 72 3c }

  condition:
    any of them
}