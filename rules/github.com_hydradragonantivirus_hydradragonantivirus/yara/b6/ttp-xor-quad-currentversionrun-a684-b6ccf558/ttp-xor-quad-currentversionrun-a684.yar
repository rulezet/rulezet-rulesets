rule TTP_XOR_QUAD_CurrentVersionRun_a684 {
  strings:
    $key_a684 = { f5 eb [2] d1 e5 [2] fa c9 [2] d4 eb [2] c0 f0 [2] cf ea [2] d1 f7 [2] d3 f6 [2] c8 f0 [2] d4 f7 [2] c8 d8 }

  condition:
    any of them
}