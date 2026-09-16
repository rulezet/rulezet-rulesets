rule TTP_XOR_QUAD_CurrentVersionRun_a6b6 {
  strings:
    $key_a6b6 = { f5 d9 [2] d1 d7 [2] fa fb [2] d4 d9 [2] c0 c2 [2] cf d8 [2] d1 c5 [2] d3 c4 [2] c8 c2 [2] d4 c5 [2] c8 ea }

  condition:
    any of them
}