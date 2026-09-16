rule TTP_XOR_QUAD_CurrentVersionRun_9297 {
  strings:
    $key_9297 = { c1 f8 [2] e5 f6 [2] ce da [2] e0 f8 [2] f4 e3 [2] fb f9 [2] e5 e4 [2] e7 e5 [2] fc e3 [2] e0 e4 [2] fc cb }

  condition:
    any of them
}