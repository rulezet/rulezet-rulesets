rule TTP_XOR_QUAD_CurrentVersionRun_9780 {
  strings:
    $key_9780 = { c4 ef [2] e0 e1 [2] cb cd [2] e5 ef [2] f1 f4 [2] fe ee [2] e0 f3 [2] e2 f2 [2] f9 f4 [2] e5 f3 [2] f9 dc }

  condition:
    any of them
}