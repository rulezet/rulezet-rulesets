rule TTP_XOR_QUAD_CurrentVersionRun_4d60 {
  strings:
    $key_4d60 = { 1e 0f [2] 3a 01 [2] 11 2d [2] 3f 0f [2] 2b 14 [2] 24 0e [2] 3a 13 [2] 38 12 [2] 23 14 [2] 3f 13 [2] 23 3c }

  condition:
    any of them
}