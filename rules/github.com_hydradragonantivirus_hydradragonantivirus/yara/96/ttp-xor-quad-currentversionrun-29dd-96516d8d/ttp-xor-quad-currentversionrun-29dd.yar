rule TTP_XOR_QUAD_CurrentVersionRun_29dd {
  strings:
    $key_29dd = { 7a b2 [2] 5e bc [2] 75 90 [2] 5b b2 [2] 4f a9 [2] 40 b3 [2] 5e ae [2] 5c af [2] 47 a9 [2] 5b ae [2] 47 81 }

  condition:
    any of them
}