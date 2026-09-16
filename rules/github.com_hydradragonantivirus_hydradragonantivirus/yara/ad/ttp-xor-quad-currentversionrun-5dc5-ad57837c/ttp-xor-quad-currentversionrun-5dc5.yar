rule TTP_XOR_QUAD_CurrentVersionRun_5dc5 {
  strings:
    $key_5dc5 = { 0e aa [2] 2a a4 [2] 01 88 [2] 2f aa [2] 3b b1 [2] 34 ab [2] 2a b6 [2] 28 b7 [2] 33 b1 [2] 2f b6 [2] 33 99 }

  condition:
    any of them
}