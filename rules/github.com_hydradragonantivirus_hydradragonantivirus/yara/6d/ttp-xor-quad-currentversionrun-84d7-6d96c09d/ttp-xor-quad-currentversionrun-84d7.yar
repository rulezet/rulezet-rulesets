rule TTP_XOR_QUAD_CurrentVersionRun_84d7 {
  strings:
    $key_84d7 = { d7 b8 [2] f3 b6 [2] d8 9a [2] f6 b8 [2] e2 a3 [2] ed b9 [2] f3 a4 [2] f1 a5 [2] ea a3 [2] f6 a4 [2] ea 8b }

  condition:
    any of them
}