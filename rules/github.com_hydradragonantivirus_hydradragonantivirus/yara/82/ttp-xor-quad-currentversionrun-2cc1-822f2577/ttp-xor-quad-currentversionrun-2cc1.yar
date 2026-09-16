rule TTP_XOR_QUAD_CurrentVersionRun_2cc1 {
  strings:
    $key_2cc1 = { 7f ae [2] 5b a0 [2] 70 8c [2] 5e ae [2] 4a b5 [2] 45 af [2] 5b b2 [2] 59 b3 [2] 42 b5 [2] 5e b2 [2] 42 9d }

  condition:
    any of them
}