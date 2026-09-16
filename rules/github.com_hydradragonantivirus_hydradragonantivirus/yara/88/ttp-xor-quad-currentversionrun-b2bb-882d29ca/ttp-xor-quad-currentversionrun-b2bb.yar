rule TTP_XOR_QUAD_CurrentVersionRun_b2bb {
  strings:
    $key_b2bb = { e1 d4 [2] c5 da [2] ee f6 [2] c0 d4 [2] d4 cf [2] db d5 [2] c5 c8 [2] c7 c9 [2] dc cf [2] c0 c8 [2] dc e7 }

  condition:
    any of them
}