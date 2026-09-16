rule TTP_XOR_QUAD_CurrentVersionRun_36d9 {
  strings:
    $key_36d9 = { 65 b6 [2] 41 b8 [2] 6a 94 [2] 44 b6 [2] 50 ad [2] 5f b7 [2] 41 aa [2] 43 ab [2] 58 ad [2] 44 aa [2] 58 85 }

  condition:
    any of them
}