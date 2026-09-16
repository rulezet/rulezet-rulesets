rule TTP_XOR_QUAD_CurrentVersionRun_b88f {
  strings:
    $key_b88f = { eb e0 [2] cf ee [2] e4 c2 [2] ca e0 [2] de fb [2] d1 e1 [2] cf fc [2] cd fd [2] d6 fb [2] ca fc [2] d6 d3 }

  condition:
    any of them
}