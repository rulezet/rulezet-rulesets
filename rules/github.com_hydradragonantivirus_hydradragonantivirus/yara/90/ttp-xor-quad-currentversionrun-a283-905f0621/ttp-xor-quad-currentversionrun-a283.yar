rule TTP_XOR_QUAD_CurrentVersionRun_a283 {
  strings:
    $key_a283 = { f1 ec [2] d5 e2 [2] fe ce [2] d0 ec [2] c4 f7 [2] cb ed [2] d5 f0 [2] d7 f1 [2] cc f7 [2] d0 f0 [2] cc df }

  condition:
    any of them
}