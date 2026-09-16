rule TTP_XOR_QUAD_CurrentVersionRun_0cc1 {
  strings:
    $key_0cc1 = { 5f ae [2] 7b a0 [2] 50 8c [2] 7e ae [2] 6a b5 [2] 65 af [2] 7b b2 [2] 79 b3 [2] 62 b5 [2] 7e b2 [2] 62 9d }

  condition:
    any of them
}