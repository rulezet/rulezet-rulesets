rule TTP_XOR_QUAD_CurrentVersionRun_5ac0 {
  strings:
    $key_5ac0 = { 09 af [2] 2d a1 [2] 06 8d [2] 28 af [2] 3c b4 [2] 33 ae [2] 2d b3 [2] 2f b2 [2] 34 b4 [2] 28 b3 [2] 34 9c }

  condition:
    any of them
}