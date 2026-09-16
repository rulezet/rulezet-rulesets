rule TTP_XOR_QUAD_CurrentVersionRun_b88d {
  strings:
    $key_b88d = { eb e2 [2] cf ec [2] e4 c0 [2] ca e2 [2] de f9 [2] d1 e3 [2] cf fe [2] cd ff [2] d6 f9 [2] ca fe [2] d6 d1 }

  condition:
    any of them
}