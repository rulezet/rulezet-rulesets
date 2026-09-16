rule TTP_XOR_QUAD_CurrentVersionRun_b483 {
  strings:
    $key_b483 = { e7 ec [2] c3 e2 [2] e8 ce [2] c6 ec [2] d2 f7 [2] dd ed [2] c3 f0 [2] c1 f1 [2] da f7 [2] c6 f0 [2] da df }

  condition:
    any of them
}