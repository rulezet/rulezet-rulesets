rule TTP_XOR_QUAD_CurrentVersionRun_b283 {
  strings:
    $key_b283 = { e1 ec [2] c5 e2 [2] ee ce [2] c0 ec [2] d4 f7 [2] db ed [2] c5 f0 [2] c7 f1 [2] dc f7 [2] c0 f0 [2] dc df }

  condition:
    any of them
}