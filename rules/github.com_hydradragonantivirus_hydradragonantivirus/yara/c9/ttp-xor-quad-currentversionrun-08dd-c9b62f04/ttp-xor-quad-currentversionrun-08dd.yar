rule TTP_XOR_QUAD_CurrentVersionRun_08dd {
  strings:
    $key_08dd = { 5b b2 [2] 7f bc [2] 54 90 [2] 7a b2 [2] 6e a9 [2] 61 b3 [2] 7f ae [2] 7d af [2] 66 a9 [2] 7a ae [2] 66 81 }

  condition:
    any of them
}