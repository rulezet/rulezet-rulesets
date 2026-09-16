rule TTP_XOR_QUAD_CurrentVersionRun_9597 {
  strings:
    $key_9597 = { c6 f8 [2] e2 f6 [2] c9 da [2] e7 f8 [2] f3 e3 [2] fc f9 [2] e2 e4 [2] e0 e5 [2] fb e3 [2] e7 e4 [2] fb cb }

  condition:
    any of them
}