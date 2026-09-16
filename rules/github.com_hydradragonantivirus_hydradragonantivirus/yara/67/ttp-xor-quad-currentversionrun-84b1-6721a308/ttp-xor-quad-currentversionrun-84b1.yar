rule TTP_XOR_QUAD_CurrentVersionRun_84b1 {
  strings:
    $key_84b1 = { d7 de [2] f3 d0 [2] d8 fc [2] f6 de [2] e2 c5 [2] ed df [2] f3 c2 [2] f1 c3 [2] ea c5 [2] f6 c2 [2] ea ed }

  condition:
    any of them
}