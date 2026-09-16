rule TTP_XOR_QUAD_CurrentVersionRun_18d9 {
  strings:
    $key_18d9 = { 4b b6 [2] 6f b8 [2] 44 94 [2] 6a b6 [2] 7e ad [2] 71 b7 [2] 6f aa [2] 6d ab [2] 76 ad [2] 6a aa [2] 76 85 }

  condition:
    any of them
}