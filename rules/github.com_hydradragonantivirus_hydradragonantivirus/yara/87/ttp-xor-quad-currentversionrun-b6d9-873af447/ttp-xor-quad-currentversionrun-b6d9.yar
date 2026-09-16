rule TTP_XOR_QUAD_CurrentVersionRun_b6d9 {
  strings:
    $key_b6d9 = { e5 b6 [2] c1 b8 [2] ea 94 [2] c4 b6 [2] d0 ad [2] df b7 [2] c1 aa [2] c3 ab [2] d8 ad [2] c4 aa [2] d8 85 }

  condition:
    any of them
}