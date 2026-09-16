rule TTP_XOR_QUAD_CurrentVersionRun_b2b3 {
  strings:
    $key_b2b3 = { e1 dc [2] c5 d2 [2] ee fe [2] c0 dc [2] d4 c7 [2] db dd [2] c5 c0 [2] c7 c1 [2] dc c7 [2] c0 c0 [2] dc ef }

  condition:
    any of them
}