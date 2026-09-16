rule TTP_XOR_QUAD_CurrentVersionRun_1cc1 {
  strings:
    $key_1cc1 = { 4f ae [2] 6b a0 [2] 40 8c [2] 6e ae [2] 7a b5 [2] 75 af [2] 6b b2 [2] 69 b3 [2] 72 b5 [2] 6e b2 [2] 72 9d }

  condition:
    any of them
}