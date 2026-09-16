rule TTP_XOR_QUAD_CurrentVersionRun_7cc5 {
  strings:
    $key_7cc5 = { 2f aa [2] 0b a4 [2] 20 88 [2] 0e aa [2] 1a b1 [2] 15 ab [2] 0b b6 [2] 09 b7 [2] 12 b1 [2] 0e b6 [2] 12 99 }

  condition:
    any of them
}