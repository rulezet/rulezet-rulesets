rule TTP_XOR_QUAD_CurrentVersionRun_b89d {
  strings:
    $key_b89d = { eb f2 [2] cf fc [2] e4 d0 [2] ca f2 [2] de e9 [2] d1 f3 [2] cf ee [2] cd ef [2] d6 e9 [2] ca ee [2] d6 c1 }

  condition:
    any of them
}