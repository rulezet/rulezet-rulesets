rule TTP_XOR_QUAD_CurrentVersionRun_b1c5 {
  strings:
    $key_b1c5 = { e2 aa [2] c6 a4 [2] ed 88 [2] c3 aa [2] d7 b1 [2] d8 ab [2] c6 b6 [2] c4 b7 [2] df b1 [2] c3 b6 [2] df 99 }

  condition:
    any of them
}