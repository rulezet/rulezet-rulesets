rule TTP_XOR_QUAD_CurrentVersionRun_5cc5 {
  strings:
    $key_5cc5 = { 0f aa [2] 2b a4 [2] 00 88 [2] 2e aa [2] 3a b1 [2] 35 ab [2] 2b b6 [2] 29 b7 [2] 32 b1 [2] 2e b6 [2] 32 99 }

  condition:
    any of them
}