rule TTP_XOR_QUAD_CurrentVersionRun_39d9 {
  strings:
    $key_39d9 = { 6a b6 [2] 4e b8 [2] 65 94 [2] 4b b6 [2] 5f ad [2] 50 b7 [2] 4e aa [2] 4c ab [2] 57 ad [2] 4b aa [2] 57 85 }

  condition:
    any of them
}