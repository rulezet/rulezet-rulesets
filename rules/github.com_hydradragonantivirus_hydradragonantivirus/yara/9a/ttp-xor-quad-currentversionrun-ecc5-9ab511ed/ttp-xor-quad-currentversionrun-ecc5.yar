rule TTP_XOR_QUAD_CurrentVersionRun_ecc5 {
  strings:
    $key_ecc5 = { bf aa [2] 9b a4 [2] b0 88 [2] 9e aa [2] 8a b1 [2] 85 ab [2] 9b b6 [2] 99 b7 [2] 82 b1 [2] 9e b6 [2] 82 99 }

  condition:
    any of them
}