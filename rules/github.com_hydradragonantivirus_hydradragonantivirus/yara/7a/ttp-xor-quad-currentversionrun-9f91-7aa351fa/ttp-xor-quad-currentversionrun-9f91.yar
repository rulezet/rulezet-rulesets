rule TTP_XOR_QUAD_CurrentVersionRun_9f91 {
  strings:
    $key_9f91 = { cc fe [2] e8 f0 [2] c3 dc [2] ed fe [2] f9 e5 [2] f6 ff [2] e8 e2 [2] ea e3 [2] f1 e5 [2] ed e2 [2] f1 cd }

  condition:
    any of them
}