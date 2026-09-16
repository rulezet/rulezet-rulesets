rule TTP_XOR_QUAD_CurrentVersionRun_3b60 {
  strings:
    $key_3b60 = { 68 0f [2] 4c 01 [2] 67 2d [2] 49 0f [2] 5d 14 [2] 52 0e [2] 4c 13 [2] 4e 12 [2] 55 14 [2] 49 13 [2] 55 3c }

  condition:
    any of them
}