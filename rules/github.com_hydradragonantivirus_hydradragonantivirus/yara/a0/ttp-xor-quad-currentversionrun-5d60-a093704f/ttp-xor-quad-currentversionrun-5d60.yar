rule TTP_XOR_QUAD_CurrentVersionRun_5d60 {
  strings:
    $key_5d60 = { 0e 0f [2] 2a 01 [2] 01 2d [2] 2f 0f [2] 3b 14 [2] 34 0e [2] 2a 13 [2] 28 12 [2] 33 14 [2] 2f 13 [2] 33 3c }

  condition:
    any of them
}