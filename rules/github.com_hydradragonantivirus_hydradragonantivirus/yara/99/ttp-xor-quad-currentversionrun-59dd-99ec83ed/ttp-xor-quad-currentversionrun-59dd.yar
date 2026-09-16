rule TTP_XOR_QUAD_CurrentVersionRun_59dd {
  strings:
    $key_59dd = { 0a b2 [2] 2e bc [2] 05 90 [2] 2b b2 [2] 3f a9 [2] 30 b3 [2] 2e ae [2] 2c af [2] 37 a9 [2] 2b ae [2] 37 81 }

  condition:
    any of them
}