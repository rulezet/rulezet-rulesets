rule TTP_XOR_QUAD_CurrentVersionRun_28c1 {
  strings:
    $key_28c1 = { 7b ae [2] 5f a0 [2] 74 8c [2] 5a ae [2] 4e b5 [2] 41 af [2] 5f b2 [2] 5d b3 [2] 46 b5 [2] 5a b2 [2] 46 9d }

  condition:
    any of them
}