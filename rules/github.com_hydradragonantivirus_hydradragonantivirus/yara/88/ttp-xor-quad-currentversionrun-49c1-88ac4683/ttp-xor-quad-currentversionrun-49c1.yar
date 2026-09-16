rule TTP_XOR_QUAD_CurrentVersionRun_49c1 {
  strings:
    $key_49c1 = { 1a ae [2] 3e a0 [2] 15 8c [2] 3b ae [2] 2f b5 [2] 20 af [2] 3e b2 [2] 3c b3 [2] 27 b5 [2] 3b b2 [2] 27 9d }

  condition:
    any of them
}