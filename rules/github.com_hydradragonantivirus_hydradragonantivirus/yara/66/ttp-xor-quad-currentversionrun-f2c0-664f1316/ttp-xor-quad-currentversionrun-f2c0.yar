rule TTP_XOR_QUAD_CurrentVersionRun_f2c0 {
  strings:
    $key_f2c0 = { a1 af [2] 85 a1 [2] ae 8d [2] 80 af [2] 94 b4 [2] 9b ae [2] 85 b3 [2] 87 b2 [2] 9c b4 [2] 80 b3 [2] 9c 9c }

  condition:
    any of them
}