rule TTP_XOR_QUAD_CurrentVersionRun_0e60 {
  strings:
    $key_0e60 = { 5d 0f [2] 79 01 [2] 52 2d [2] 7c 0f [2] 68 14 [2] 67 0e [2] 79 13 [2] 7b 12 [2] 60 14 [2] 7c 13 [2] 60 3c }

  condition:
    any of them
}