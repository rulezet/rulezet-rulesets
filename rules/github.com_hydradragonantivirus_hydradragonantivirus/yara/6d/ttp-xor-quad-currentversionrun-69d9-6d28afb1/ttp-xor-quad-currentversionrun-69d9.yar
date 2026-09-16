rule TTP_XOR_QUAD_CurrentVersionRun_69d9 {
  strings:
    $key_69d9 = { 3a b6 [2] 1e b8 [2] 35 94 [2] 1b b6 [2] 0f ad [2] 00 b7 [2] 1e aa [2] 1c ab [2] 07 ad [2] 1b aa [2] 07 85 }

  condition:
    any of them
}