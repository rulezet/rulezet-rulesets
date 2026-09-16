rule TTP_XOR_QUAD_CurrentVersionRun_b591 {
  strings:
    $key_b591 = { e6 fe [2] c2 f0 [2] e9 dc [2] c7 fe [2] d3 e5 [2] dc ff [2] c2 e2 [2] c0 e3 [2] db e5 [2] c7 e2 [2] db cd }

  condition:
    any of them
}