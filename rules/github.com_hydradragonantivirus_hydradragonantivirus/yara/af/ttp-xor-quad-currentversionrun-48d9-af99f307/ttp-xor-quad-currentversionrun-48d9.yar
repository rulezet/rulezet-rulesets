rule TTP_XOR_QUAD_CurrentVersionRun_48d9 {
  strings:
    $key_48d9 = { 1b b6 [2] 3f b8 [2] 14 94 [2] 3a b6 [2] 2e ad [2] 21 b7 [2] 3f aa [2] 3d ab [2] 26 ad [2] 3a aa [2] 26 85 }

  condition:
    any of them
}