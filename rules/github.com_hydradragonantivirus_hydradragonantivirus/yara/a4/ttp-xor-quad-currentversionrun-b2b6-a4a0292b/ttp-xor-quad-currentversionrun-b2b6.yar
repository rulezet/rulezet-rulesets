rule TTP_XOR_QUAD_CurrentVersionRun_b2b6 {
  strings:
    $key_b2b6 = { e1 d9 [2] c5 d7 [2] ee fb [2] c0 d9 [2] d4 c2 [2] db d8 [2] c5 c5 [2] c7 c4 [2] dc c2 [2] c0 c5 [2] dc ea }

  condition:
    any of them
}