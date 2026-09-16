rule TTP_XOR_QUAD_CurrentVersionRun_49d9 {
  strings:
    $key_49d9 = { 1a b6 [2] 3e b8 [2] 15 94 [2] 3b b6 [2] 2f ad [2] 20 b7 [2] 3e aa [2] 3c ab [2] 27 ad [2] 3b aa [2] 27 85 }

  condition:
    any of them
}