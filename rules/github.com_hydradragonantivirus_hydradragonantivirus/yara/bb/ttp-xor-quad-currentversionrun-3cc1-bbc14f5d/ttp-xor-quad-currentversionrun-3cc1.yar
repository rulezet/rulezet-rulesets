rule TTP_XOR_QUAD_CurrentVersionRun_3cc1 {
  strings:
    $key_3cc1 = { 6f ae [2] 4b a0 [2] 60 8c [2] 4e ae [2] 5a b5 [2] 55 af [2] 4b b2 [2] 49 b3 [2] 52 b5 [2] 4e b2 [2] 52 9d }

  condition:
    any of them
}