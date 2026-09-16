rule TTP_XOR_QUAD_CurrentVersionRun_29c1 {
  strings:
    $key_29c1 = { 7a ae [2] 5e a0 [2] 75 8c [2] 5b ae [2] 4f b5 [2] 40 af [2] 5e b2 [2] 5c b3 [2] 47 b5 [2] 5b b2 [2] 47 9d }

  condition:
    any of them
}