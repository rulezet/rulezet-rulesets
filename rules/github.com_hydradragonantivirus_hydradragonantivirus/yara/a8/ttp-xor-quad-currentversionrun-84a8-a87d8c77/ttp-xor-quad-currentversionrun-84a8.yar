rule TTP_XOR_QUAD_CurrentVersionRun_84a8 {
  strings:
    $key_84a8 = { d7 c7 [2] f3 c9 [2] d8 e5 [2] f6 c7 [2] e2 dc [2] ed c6 [2] f3 db [2] f1 da [2] ea dc [2] f6 db [2] ea f4 }

  condition:
    any of them
}