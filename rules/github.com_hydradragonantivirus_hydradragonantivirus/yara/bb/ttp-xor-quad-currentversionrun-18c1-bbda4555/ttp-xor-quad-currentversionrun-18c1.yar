rule TTP_XOR_QUAD_CurrentVersionRun_18c1 {
  strings:
    $key_18c1 = { 4b ae [2] 6f a0 [2] 44 8c [2] 6a ae [2] 7e b5 [2] 71 af [2] 6f b2 [2] 6d b3 [2] 76 b5 [2] 6a b2 [2] 76 9d }

  condition:
    any of them
}