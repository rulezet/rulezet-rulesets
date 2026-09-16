rule TTP_XOR_QUAD_CurrentVersionRun_b7d9 {
  strings:
    $key_b7d9 = { e4 b6 [2] c0 b8 [2] eb 94 [2] c5 b6 [2] d1 ad [2] de b7 [2] c0 aa [2] c2 ab [2] d9 ad [2] c5 aa [2] d9 85 }

  condition:
    any of them
}