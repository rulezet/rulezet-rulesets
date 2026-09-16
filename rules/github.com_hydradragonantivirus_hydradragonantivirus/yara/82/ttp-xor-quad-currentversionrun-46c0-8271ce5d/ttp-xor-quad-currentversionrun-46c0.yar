rule TTP_XOR_QUAD_CurrentVersionRun_46c0 {
  strings:
    $key_46c0 = { 15 af [2] 31 a1 [2] 1a 8d [2] 34 af [2] 20 b4 [2] 2f ae [2] 31 b3 [2] 33 b2 [2] 28 b4 [2] 34 b3 [2] 28 9c }

  condition:
    any of them
}