rule TTP_XOR_QUAD_CurrentVersionRun_b2a6 {
  strings:
    $key_b2a6 = { e1 c9 [2] c5 c7 [2] ee eb [2] c0 c9 [2] d4 d2 [2] db c8 [2] c5 d5 [2] c7 d4 [2] dc d2 [2] c0 d5 [2] dc fa }

  condition:
    any of them
}