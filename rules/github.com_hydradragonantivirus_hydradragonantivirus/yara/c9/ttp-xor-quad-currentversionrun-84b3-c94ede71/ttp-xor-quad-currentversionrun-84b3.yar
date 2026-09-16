rule TTP_XOR_QUAD_CurrentVersionRun_84b3 {
  strings:
    $key_84b3 = { d7 dc [2] f3 d2 [2] d8 fe [2] f6 dc [2] e2 c7 [2] ed dd [2] f3 c0 [2] f1 c1 [2] ea c7 [2] f6 c0 [2] ea ef }

  condition:
    any of them
}