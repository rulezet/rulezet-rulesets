rule TTP_XOR_QUAD_CurrentVersionRun_3cd9 {
  strings:
    $key_3cd9 = { 6f b6 [2] 4b b8 [2] 60 94 [2] 4e b6 [2] 5a ad [2] 55 b7 [2] 4b aa [2] 49 ab [2] 52 ad [2] 4e aa [2] 52 85 }

  condition:
    any of them
}