rule TTP_XOR_QUAD_CurrentVersionRun_3597 {
  strings:
    $key_3597 = { 66 f8 [2] 42 f6 [2] 69 da [2] 47 f8 [2] 53 e3 [2] 5c f9 [2] 42 e4 [2] 40 e5 [2] 5b e3 [2] 47 e4 [2] 5b cb }

  condition:
    any of them
}