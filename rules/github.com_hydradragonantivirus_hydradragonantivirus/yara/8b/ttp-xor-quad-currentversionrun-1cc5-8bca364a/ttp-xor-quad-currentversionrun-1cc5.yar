rule TTP_XOR_QUAD_CurrentVersionRun_1cc5 {
  strings:
    $key_1cc5 = { 4f aa [2] 6b a4 [2] 40 88 [2] 6e aa [2] 7a b1 [2] 75 ab [2] 6b b6 [2] 69 b7 [2] 72 b1 [2] 6e b6 [2] 72 99 }

  condition:
    any of them
}