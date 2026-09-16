rule TTP_XOR_QUAD_CurrentVersionRun_78d9 {
  strings:
    $key_78d9 = { 2b b6 [2] 0f b8 [2] 24 94 [2] 0a b6 [2] 1e ad [2] 11 b7 [2] 0f aa [2] 0d ab [2] 16 ad [2] 0a aa [2] 16 85 }

  condition:
    any of them
}