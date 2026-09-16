rule TTP_XOR_QUAD_CurrentVersionRun_84b4 {
  strings:
    $key_84b4 = { d7 db [2] f3 d5 [2] d8 f9 [2] f6 db [2] e2 c0 [2] ed da [2] f3 c7 [2] f1 c6 [2] ea c0 [2] f6 c7 [2] ea e8 }

  condition:
    any of them
}