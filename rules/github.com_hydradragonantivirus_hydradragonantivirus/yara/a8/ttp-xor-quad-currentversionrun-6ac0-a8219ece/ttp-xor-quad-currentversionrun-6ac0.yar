rule TTP_XOR_QUAD_CurrentVersionRun_6ac0 {
  strings:
    $key_6ac0 = { 39 af [2] 1d a1 [2] 36 8d [2] 18 af [2] 0c b4 [2] 03 ae [2] 1d b3 [2] 1f b2 [2] 04 b4 [2] 18 b3 [2] 04 9c }

  condition:
    any of them
}