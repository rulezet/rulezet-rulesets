rule TTP_XOR_QUAD_CurrentVersionRun_9781 {
  strings:
    $key_9781 = { c4 ee [2] e0 e0 [2] cb cc [2] e5 ee [2] f1 f5 [2] fe ef [2] e0 f2 [2] e2 f3 [2] f9 f5 [2] e5 f2 [2] f9 dd }

  condition:
    any of them
}