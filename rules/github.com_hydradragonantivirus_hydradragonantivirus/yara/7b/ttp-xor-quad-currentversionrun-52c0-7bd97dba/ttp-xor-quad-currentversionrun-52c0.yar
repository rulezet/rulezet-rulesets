rule TTP_XOR_QUAD_CurrentVersionRun_52c0 {
  strings:
    $key_52c0 = { 01 af [2] 25 a1 [2] 0e 8d [2] 20 af [2] 34 b4 [2] 3b ae [2] 25 b3 [2] 27 b2 [2] 3c b4 [2] 20 b3 [2] 3c 9c }

  condition:
    any of them
}