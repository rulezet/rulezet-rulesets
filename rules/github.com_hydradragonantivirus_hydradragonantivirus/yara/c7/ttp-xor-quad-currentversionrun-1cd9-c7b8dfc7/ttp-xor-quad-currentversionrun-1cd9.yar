rule TTP_XOR_QUAD_CurrentVersionRun_1cd9 {
  strings:
    $key_1cd9 = { 4f b6 [2] 6b b8 [2] 40 94 [2] 6e b6 [2] 7a ad [2] 75 b7 [2] 6b aa [2] 69 ab [2] 72 ad [2] 6e aa [2] 72 85 }

  condition:
    any of them
}