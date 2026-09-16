rule TTP_XOR_QUAD_CurrentVersionRun_b598 {
  strings:
    $key_b598 = { e6 f7 [2] c2 f9 [2] e9 d5 [2] c7 f7 [2] d3 ec [2] dc f6 [2] c2 eb [2] c0 ea [2] db ec [2] c7 eb [2] db c4 }

  condition:
    any of them
}