rule TTP_XOR_QUAD_CurrentVersionRun_9797 {
  strings:
    $key_9797 = { c4 f8 [2] e0 f6 [2] cb da [2] e5 f8 [2] f1 e3 [2] fe f9 [2] e0 e4 [2] e2 e5 [2] f9 e3 [2] e5 e4 [2] f9 cb }

  condition:
    any of them
}