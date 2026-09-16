rule TTP_XOR_QUAD_CurrentVersionRun_2cd9 {
  strings:
    $key_2cd9 = { 7f b6 [2] 5b b8 [2] 70 94 [2] 5e b6 [2] 4a ad [2] 45 b7 [2] 5b aa [2] 59 ab [2] 42 ad [2] 5e aa [2] 42 85 }

  condition:
    any of them
}