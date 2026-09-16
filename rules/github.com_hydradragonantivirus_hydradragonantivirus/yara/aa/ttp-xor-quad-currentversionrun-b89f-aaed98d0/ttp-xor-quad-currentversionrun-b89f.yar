rule TTP_XOR_QUAD_CurrentVersionRun_b89f {
  strings:
    $key_b89f = { eb f0 [2] cf fe [2] e4 d2 [2] ca f0 [2] de eb [2] d1 f1 [2] cf ec [2] cd ed [2] d6 eb [2] ca ec [2] d6 c3 }

  condition:
    any of them
}