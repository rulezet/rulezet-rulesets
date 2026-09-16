rule TTP_XOR_QUAD_CurrentVersionRun_b596 {
  strings:
    $key_b596 = { e6 f9 [2] c2 f7 [2] e9 db [2] c7 f9 [2] d3 e2 [2] dc f8 [2] c2 e5 [2] c0 e4 [2] db e2 [2] c7 e5 [2] db ca }

  condition:
    any of them
}