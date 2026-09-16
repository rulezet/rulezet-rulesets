rule TTP_XOR_QUAD_CurrentVersionRun_48dd {
  strings:
    $key_48dd = { 1b b2 [2] 3f bc [2] 14 90 [2] 3a b2 [2] 2e a9 [2] 21 b3 [2] 3f ae [2] 3d af [2] 26 a9 [2] 3a ae [2] 26 81 }

  condition:
    any of them
}