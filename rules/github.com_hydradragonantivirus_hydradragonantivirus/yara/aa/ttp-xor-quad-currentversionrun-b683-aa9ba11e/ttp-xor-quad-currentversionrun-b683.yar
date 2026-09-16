rule TTP_XOR_QUAD_CurrentVersionRun_b683 {
  strings:
    $key_b683 = { e5 ec [2] c1 e2 [2] ea ce [2] c4 ec [2] d0 f7 [2] df ed [2] c1 f0 [2] c3 f1 [2] d8 f7 [2] c4 f0 [2] d8 df }

  condition:
    any of them
}