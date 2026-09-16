rule TTP_XOR_QUAD_CurrentVersionRun_84a6 {
  strings:
    $key_84a6 = { d7 c9 [2] f3 c7 [2] d8 eb [2] f6 c9 [2] e2 d2 [2] ed c8 [2] f3 d5 [2] f1 d4 [2] ea d2 [2] f6 d5 [2] ea fa }

  condition:
    any of them
}