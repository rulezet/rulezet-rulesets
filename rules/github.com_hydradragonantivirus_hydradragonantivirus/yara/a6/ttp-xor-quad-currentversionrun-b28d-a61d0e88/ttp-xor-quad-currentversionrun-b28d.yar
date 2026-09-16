rule TTP_XOR_QUAD_CurrentVersionRun_b28d {
  strings:
    $key_b28d = { e1 e2 [2] c5 ec [2] ee c0 [2] c0 e2 [2] d4 f9 [2] db e3 [2] c5 fe [2] c7 ff [2] dc f9 [2] c0 fe [2] dc d1 }

  condition:
    any of them
}