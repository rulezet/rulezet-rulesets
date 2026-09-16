rule TTP_XOR_QUAD_CurrentVersionRun_84f7 {
  strings:
    $key_84f7 = { d7 98 [2] f3 96 [2] d8 ba [2] f6 98 [2] e2 83 [2] ed 99 [2] f3 84 [2] f1 85 [2] ea 83 [2] f6 84 [2] ea ab }

  condition:
    any of them
}