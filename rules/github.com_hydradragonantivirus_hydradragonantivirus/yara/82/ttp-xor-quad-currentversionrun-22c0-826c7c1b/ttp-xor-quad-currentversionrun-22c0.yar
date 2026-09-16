rule TTP_XOR_QUAD_CurrentVersionRun_22c0 {
  strings:
    $key_22c0 = { 71 af [2] 55 a1 [2] 7e 8d [2] 50 af [2] 44 b4 [2] 4b ae [2] 55 b3 [2] 57 b2 [2] 4c b4 [2] 50 b3 [2] 4c 9c }

  condition:
    any of them
}