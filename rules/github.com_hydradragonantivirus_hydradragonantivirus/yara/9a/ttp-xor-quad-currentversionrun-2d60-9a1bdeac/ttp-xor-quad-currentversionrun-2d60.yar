rule TTP_XOR_QUAD_CurrentVersionRun_2d60 {
  strings:
    $key_2d60 = { 7e 0f [2] 5a 01 [2] 71 2d [2] 5f 0f [2] 4b 14 [2] 44 0e [2] 5a 13 [2] 58 12 [2] 43 14 [2] 5f 13 [2] 43 3c }

  condition:
    any of them
}