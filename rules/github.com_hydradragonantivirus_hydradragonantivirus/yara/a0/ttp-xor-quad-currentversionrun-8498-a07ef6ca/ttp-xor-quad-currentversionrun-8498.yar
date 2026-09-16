rule TTP_XOR_QUAD_CurrentVersionRun_8498 {
  strings:
    $key_8498 = { d7 f7 [2] f3 f9 [2] d8 d5 [2] f6 f7 [2] e2 ec [2] ed f6 [2] f3 eb [2] f1 ea [2] ea ec [2] f6 eb [2] ea c4 }

  condition:
    any of them
}