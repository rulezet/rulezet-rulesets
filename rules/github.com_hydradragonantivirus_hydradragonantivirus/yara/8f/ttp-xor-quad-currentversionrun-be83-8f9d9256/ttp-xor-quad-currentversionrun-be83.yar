rule TTP_XOR_QUAD_CurrentVersionRun_be83 {
  strings:
    $key_be83 = { ed ec [2] c9 e2 [2] e2 ce [2] cc ec [2] d8 f7 [2] d7 ed [2] c9 f0 [2] cb f1 [2] d0 f7 [2] cc f0 [2] d0 df }

  condition:
    any of them
}