rule TTP_XOR_QUAD_CurrentVersionRun_68c1 {
  strings:
    $key_68c1 = { 3b ae [2] 1f a0 [2] 34 8c [2] 1a ae [2] 0e b5 [2] 01 af [2] 1f b2 [2] 1d b3 [2] 06 b5 [2] 1a b2 [2] 06 9d }

  condition:
    any of them
}