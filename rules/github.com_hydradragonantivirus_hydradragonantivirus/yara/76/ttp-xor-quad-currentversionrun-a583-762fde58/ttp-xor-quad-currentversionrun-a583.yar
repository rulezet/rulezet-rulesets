rule TTP_XOR_QUAD_CurrentVersionRun_a583 {
  strings:
    $key_a583 = { f6 ec [2] d2 e2 [2] f9 ce [2] d7 ec [2] c3 f7 [2] cc ed [2] d2 f0 [2] d0 f1 [2] cb f7 [2] d7 f0 [2] cb df }

  condition:
    any of them
}