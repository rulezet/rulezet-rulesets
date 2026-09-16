rule TTP_XOR_QUAD_CurrentVersionRun_9497 {
  strings:
    $key_9497 = { c7 f8 [2] e3 f6 [2] c8 da [2] e6 f8 [2] f2 e3 [2] fd f9 [2] e3 e4 [2] e1 e5 [2] fa e3 [2] e6 e4 [2] fa cb }

  condition:
    any of them
}