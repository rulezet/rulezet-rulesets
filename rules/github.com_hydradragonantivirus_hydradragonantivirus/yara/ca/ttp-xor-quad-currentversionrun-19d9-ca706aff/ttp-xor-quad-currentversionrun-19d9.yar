rule TTP_XOR_QUAD_CurrentVersionRun_19d9 {
  strings:
    $key_19d9 = { 4a b6 [2] 6e b8 [2] 45 94 [2] 6b b6 [2] 7f ad [2] 70 b7 [2] 6e aa [2] 6c ab [2] 77 ad [2] 6b aa [2] 77 85 }

  condition:
    any of them
}