rule TTP_XOR_QUAD_CurrentVersionRun_1760 {
  strings:
    $key_1760 = { 44 0f [2] 60 01 [2] 4b 2d [2] 65 0f [2] 71 14 [2] 7e 0e [2] 60 13 [2] 62 12 [2] 79 14 [2] 65 13 [2] 79 3c }

  condition:
    any of them
}