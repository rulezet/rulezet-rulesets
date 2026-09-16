rule TTP_XOR_QUAD_CurrentVersionRun_9fd3 {
  strings:
    $key_9fd3 = { cc bc [2] e8 b2 [2] c3 9e [2] ed bc [2] f9 a7 [2] f6 bd [2] e8 a0 [2] ea a1 [2] f1 a7 [2] ed a0 [2] f1 8f }

  condition:
    any of them
}