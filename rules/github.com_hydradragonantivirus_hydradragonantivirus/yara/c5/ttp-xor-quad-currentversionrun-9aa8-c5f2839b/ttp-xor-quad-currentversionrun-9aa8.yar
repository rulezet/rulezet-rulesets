rule TTP_XOR_QUAD_CurrentVersionRun_9aa8 {
  strings:
    $key_9aa8 = { c9 c7 [2] ed c9 [2] c6 e5 [2] e8 c7 [2] fc dc [2] f3 c6 [2] ed db [2] ef da [2] f4 dc [2] e8 db [2] f4 f4 }

  condition:
    any of them
}