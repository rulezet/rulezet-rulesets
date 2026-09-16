rule TTP_XOR_QUAD_CurrentVersionRun_9790 {
  strings:
    $key_9790 = { c4 ff [2] e0 f1 [2] cb dd [2] e5 ff [2] f1 e4 [2] fe fe [2] e0 e3 [2] e2 e2 [2] f9 e4 [2] e5 e3 [2] f9 cc }

  condition:
    any of them
}