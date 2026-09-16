rule TTP_XOR_QUAD_CurrentVersionRun_4dc1 {
  strings:
    $key_4dc1 = { 1e ae [2] 3a a0 [2] 11 8c [2] 3f ae [2] 2b b5 [2] 24 af [2] 3a b2 [2] 38 b3 [2] 23 b5 [2] 3f b2 [2] 23 9d }

  condition:
    any of them
}