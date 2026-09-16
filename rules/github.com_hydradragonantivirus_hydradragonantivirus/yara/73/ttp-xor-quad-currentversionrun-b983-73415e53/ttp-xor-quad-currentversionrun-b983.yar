rule TTP_XOR_QUAD_CurrentVersionRun_b983 {
  strings:
    $key_b983 = { ea ec [2] ce e2 [2] e5 ce [2] cb ec [2] df f7 [2] d0 ed [2] ce f0 [2] cc f1 [2] d7 f7 [2] cb f0 [2] d7 df }

  condition:
    any of them
}