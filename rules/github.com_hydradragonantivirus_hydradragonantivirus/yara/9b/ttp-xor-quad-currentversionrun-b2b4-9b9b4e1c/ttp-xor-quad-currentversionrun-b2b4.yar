rule TTP_XOR_QUAD_CurrentVersionRun_b2b4 {
  strings:
    $key_b2b4 = { e1 db [2] c5 d5 [2] ee f9 [2] c0 db [2] d4 c0 [2] db da [2] c5 c7 [2] c7 c6 [2] dc c0 [2] c0 c7 [2] dc e8 }

  condition:
    any of them
}