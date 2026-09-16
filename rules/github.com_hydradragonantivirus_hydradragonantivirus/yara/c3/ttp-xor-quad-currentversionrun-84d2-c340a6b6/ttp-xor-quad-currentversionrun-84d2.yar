rule TTP_XOR_QUAD_CurrentVersionRun_84d2 {
  strings:
    $key_84d2 = { d7 bd [2] f3 b3 [2] d8 9f [2] f6 bd [2] e2 a6 [2] ed bc [2] f3 a1 [2] f1 a0 [2] ea a6 [2] f6 a1 [2] ea 8e }

  condition:
    any of them
}