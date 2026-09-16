rule TTP_XOR_QUAD_CurrentVersionRun_1260 {
  strings:
    $key_1260 = { 41 0f [2] 65 01 [2] 4e 2d [2] 60 0f [2] 74 14 [2] 7b 0e [2] 65 13 [2] 67 12 [2] 7c 14 [2] 60 13 [2] 7c 3c }

  condition:
    any of them
}