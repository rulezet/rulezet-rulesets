rule TTP_XOR_QUAD_CurrentVersionRun_b7b6 {
  strings:
    $key_b7b6 = { e4 d9 [2] c0 d7 [2] eb fb [2] c5 d9 [2] d1 c2 [2] de d8 [2] c0 c5 [2] c2 c4 [2] d9 c2 [2] c5 c5 [2] d9 ea }

  condition:
    any of them
}