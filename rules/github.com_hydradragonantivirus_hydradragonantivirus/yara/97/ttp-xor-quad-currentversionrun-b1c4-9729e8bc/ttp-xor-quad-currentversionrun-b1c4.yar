rule TTP_XOR_QUAD_CurrentVersionRun_b1c4 {
  strings:
    $key_b1c4 = { e2 ab [2] c6 a5 [2] ed 89 [2] c3 ab [2] d7 b0 [2] d8 aa [2] c6 b7 [2] c4 b6 [2] df b0 [2] c3 b7 [2] df 98 }

  condition:
    any of them
}