rule TTP_XOR_QUAD_CurrentVersionRun_0cd9 {
  strings:
    $key_0cd9 = { 5f b6 [2] 7b b8 [2] 50 94 [2] 7e b6 [2] 6a ad [2] 65 b7 [2] 7b aa [2] 79 ab [2] 62 ad [2] 7e aa [2] 62 85 }

  condition:
    any of them
}