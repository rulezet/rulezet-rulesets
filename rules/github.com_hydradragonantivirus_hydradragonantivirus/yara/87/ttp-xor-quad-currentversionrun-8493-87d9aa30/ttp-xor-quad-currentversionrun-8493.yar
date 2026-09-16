rule TTP_XOR_QUAD_CurrentVersionRun_8493 {
  strings:
    $key_8493 = { d7 fc [2] f3 f2 [2] d8 de [2] f6 fc [2] e2 e7 [2] ed fd [2] f3 e0 [2] f1 e1 [2] ea e7 [2] f6 e0 [2] ea cf }

  condition:
    any of them
}