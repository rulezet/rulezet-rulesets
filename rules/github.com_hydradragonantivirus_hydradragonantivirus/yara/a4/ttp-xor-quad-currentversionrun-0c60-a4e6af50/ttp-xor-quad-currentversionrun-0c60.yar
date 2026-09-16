rule TTP_XOR_QUAD_CurrentVersionRun_0c60 {
  strings:
    $key_0c60 = { 5f 0f [2] 7b 01 [2] 50 2d [2] 7e 0f [2] 6a 14 [2] 65 0e [2] 7b 13 [2] 79 12 [2] 62 14 [2] 7e 13 [2] 62 3c }

  condition:
    any of them
}