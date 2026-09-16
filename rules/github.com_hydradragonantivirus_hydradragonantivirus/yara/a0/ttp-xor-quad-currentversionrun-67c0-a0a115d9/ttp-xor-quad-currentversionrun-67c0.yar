rule TTP_XOR_QUAD_CurrentVersionRun_67c0 {
  strings:
    $key_67c0 = { 34 af [2] 10 a1 [2] 3b 8d [2] 15 af [2] 01 b4 [2] 0e ae [2] 10 b3 [2] 12 b2 [2] 09 b4 [2] 15 b3 [2] 09 9c }

  condition:
    any of them
}