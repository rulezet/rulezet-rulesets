rule TTP_XOR_QUAD_CurrentVersionRun_9a97 {
  strings:
    $key_9a97 = { c9 f8 [2] ed f6 [2] c6 da [2] e8 f8 [2] fc e3 [2] f3 f9 [2] ed e4 [2] ef e5 [2] f4 e3 [2] e8 e4 [2] f4 cb }

  condition:
    any of them
}