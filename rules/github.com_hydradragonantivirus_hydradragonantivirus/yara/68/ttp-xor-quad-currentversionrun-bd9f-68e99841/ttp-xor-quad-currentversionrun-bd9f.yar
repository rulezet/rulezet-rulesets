rule TTP_XOR_QUAD_CurrentVersionRun_bd9f {
  strings:
    $key_bd9f = { ee f0 [2] ca fe [2] e1 d2 [2] cf f0 [2] db eb [2] d4 f1 [2] ca ec [2] c8 ed [2] d3 eb [2] cf ec [2] d3 c3 }

  condition:
    any of them
}