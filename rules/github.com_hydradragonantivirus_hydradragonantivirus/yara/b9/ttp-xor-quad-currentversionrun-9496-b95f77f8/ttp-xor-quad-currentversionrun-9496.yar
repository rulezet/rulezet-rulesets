rule TTP_XOR_QUAD_CurrentVersionRun_9496 {
  strings:
    $key_9496 = { c7 f9 [2] e3 f7 [2] c8 db [2] e6 f9 [2] f2 e2 [2] fd f8 [2] e3 e5 [2] e1 e4 [2] fa e2 [2] e6 e5 [2] fa ca }

  condition:
    any of them
}