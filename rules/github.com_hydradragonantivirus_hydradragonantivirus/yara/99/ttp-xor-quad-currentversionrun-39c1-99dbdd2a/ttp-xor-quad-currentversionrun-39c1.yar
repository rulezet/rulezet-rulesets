rule TTP_XOR_QUAD_CurrentVersionRun_39c1 {
  strings:
    $key_39c1 = { 6a ae [2] 4e a0 [2] 65 8c [2] 4b ae [2] 5f b5 [2] 50 af [2] 4e b2 [2] 4c b3 [2] 57 b5 [2] 4b b2 [2] 57 9d }

  condition:
    any of them
}