rule TTP_XOR_QUAD_CurrentVersionRun_b1b6 {
  strings:
    $key_b1b6 = { e2 d9 [2] c6 d7 [2] ed fb [2] c3 d9 [2] d7 c2 [2] d8 d8 [2] c6 c5 [2] c4 c4 [2] df c2 [2] c3 c5 [2] df ea }

  condition:
    any of them
}