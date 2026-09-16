rule TTP_XOR_QUAD_CurrentVersionRun_2dd9 {
  strings:
    $key_2dd9 = { 7e b6 [2] 5a b8 [2] 71 94 [2] 5f b6 [2] 4b ad [2] 44 b7 [2] 5a aa [2] 58 ab [2] 43 ad [2] 5f aa [2] 43 85 }

  condition:
    any of them
}