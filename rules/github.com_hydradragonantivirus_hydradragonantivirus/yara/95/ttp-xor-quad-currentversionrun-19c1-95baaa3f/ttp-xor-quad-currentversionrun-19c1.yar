rule TTP_XOR_QUAD_CurrentVersionRun_19c1 {
  strings:
    $key_19c1 = { 4a ae [2] 6e a0 [2] 45 8c [2] 6b ae [2] 7f b5 [2] 70 af [2] 6e b2 [2] 6c b3 [2] 77 b5 [2] 6b b2 [2] 77 9d }

  condition:
    any of them
}