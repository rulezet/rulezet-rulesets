rule TTP_XOR_QUAD_CurrentVersionRun_6cc5 {
  strings:
    $key_6cc5 = { 3f aa [2] 1b a4 [2] 30 88 [2] 1e aa [2] 0a b1 [2] 05 ab [2] 1b b6 [2] 19 b7 [2] 02 b1 [2] 1e b6 [2] 02 99 }

  condition:
    any of them
}