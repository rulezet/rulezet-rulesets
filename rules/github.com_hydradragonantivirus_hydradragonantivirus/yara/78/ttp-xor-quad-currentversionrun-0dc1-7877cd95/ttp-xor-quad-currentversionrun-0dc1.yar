rule TTP_XOR_QUAD_CurrentVersionRun_0dc1 {
  strings:
    $key_0dc1 = { 5e ae [2] 7a a0 [2] 51 8c [2] 7f ae [2] 6b b5 [2] 64 af [2] 7a b2 [2] 78 b3 [2] 63 b5 [2] 7f b2 [2] 63 9d }

  condition:
    any of them
}