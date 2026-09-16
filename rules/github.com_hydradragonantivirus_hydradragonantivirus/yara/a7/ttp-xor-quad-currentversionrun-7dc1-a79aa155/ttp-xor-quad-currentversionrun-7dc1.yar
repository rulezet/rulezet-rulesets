rule TTP_XOR_QUAD_CurrentVersionRun_7dc1 {
  strings:
    $key_7dc1 = { 2e ae [2] 0a a0 [2] 21 8c [2] 0f ae [2] 1b b5 [2] 14 af [2] 0a b2 [2] 08 b3 [2] 13 b5 [2] 0f b2 [2] 13 9d }

  condition:
    any of them
}