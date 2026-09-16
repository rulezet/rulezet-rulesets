rule TTP_XOR_QUAD_CurrentVersionRun_84d6 {
  strings:
    $key_84d6 = { d7 b9 [2] f3 b7 [2] d8 9b [2] f6 b9 [2] e2 a2 [2] ed b8 [2] f3 a5 [2] f1 a4 [2] ea a2 [2] f6 a5 [2] ea 8a }

  condition:
    any of them
}