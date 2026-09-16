rule TTP_XOR_QUAD_CurrentVersionRun_2ac0 {
  strings:
    $key_2ac0 = { 79 af [2] 5d a1 [2] 76 8d [2] 58 af [2] 4c b4 [2] 43 ae [2] 5d b3 [2] 5f b2 [2] 44 b4 [2] 58 b3 [2] 44 9c }

  condition:
    any of them
}