rule TTP_XOR_QUAD_CurrentVersionRun_b1d9 {
  strings:
    $key_b1d9 = { e2 b6 [2] c6 b8 [2] ed 94 [2] c3 b6 [2] d7 ad [2] d8 b7 [2] c6 aa [2] c4 ab [2] df ad [2] c3 aa [2] df 85 }

  condition:
    any of them
}