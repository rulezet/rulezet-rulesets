rule TTP_XOR_QUAD_CurrentVersionRun_b59f {
  strings:
    $key_b59f = { e6 f0 [2] c2 fe [2] e9 d2 [2] c7 f0 [2] d3 eb [2] dc f1 [2] c2 ec [2] c0 ed [2] db eb [2] c7 ec [2] db c3 }

  condition:
    any of them
}