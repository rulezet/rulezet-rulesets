rule TTP_XOR_QUAD_CurrentVersionRun_58d9 {
  strings:
    $key_58d9 = { 0b b6 [2] 2f b8 [2] 04 94 [2] 2a b6 [2] 3e ad [2] 31 b7 [2] 2f aa [2] 2d ab [2] 36 ad [2] 2a aa [2] 36 85 }

  condition:
    any of them
}