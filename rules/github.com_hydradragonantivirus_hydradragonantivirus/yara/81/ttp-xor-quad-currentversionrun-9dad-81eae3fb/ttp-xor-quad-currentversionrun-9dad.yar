rule TTP_XOR_QUAD_CurrentVersionRun_9dad {
  strings:
    $key_9dad = { ce c2 [2] ea cc [2] c1 e0 [2] ef c2 [2] fb d9 [2] f4 c3 [2] ea de [2] e8 df [2] f3 d9 [2] ef de [2] f3 f1 }

  condition:
    any of them
}