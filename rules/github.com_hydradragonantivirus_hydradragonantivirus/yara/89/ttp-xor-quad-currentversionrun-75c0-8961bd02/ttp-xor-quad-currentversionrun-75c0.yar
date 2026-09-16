rule TTP_XOR_QUAD_CurrentVersionRun_75c0 {
  strings:
    $key_75c0 = { 26 af [2] 02 a1 [2] 29 8d [2] 07 af [2] 13 b4 [2] 1c ae [2] 02 b3 [2] 00 b2 [2] 1b b4 [2] 07 b3 [2] 1b 9c }

  condition:
    any of them
}