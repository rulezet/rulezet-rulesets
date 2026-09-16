rule TTP_XOR_QUAD_CurrentVersionRun_3ac0 {
  strings:
    $key_3ac0 = { 69 af [2] 4d a1 [2] 66 8d [2] 48 af [2] 5c b4 [2] 53 ae [2] 4d b3 [2] 4f b2 [2] 54 b4 [2] 48 b3 [2] 54 9c }

  condition:
    any of them
}