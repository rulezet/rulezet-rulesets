rule TTP_XOR_QUAD_CurrentVersionRun_28d9 {
  strings:
    $key_28d9 = { 7b b6 [2] 5f b8 [2] 74 94 [2] 5a b6 [2] 4e ad [2] 41 b7 [2] 5f aa [2] 5d ab [2] 46 ad [2] 5a aa [2] 46 85 }

  condition:
    any of them
}