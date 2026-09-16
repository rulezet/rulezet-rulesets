rule TTP_XOR_QUAD_CurrentVersionRun_848a {
  strings:
    $key_848a = { d7 e5 [2] f3 eb [2] d8 c7 [2] f6 e5 [2] e2 fe [2] ed e4 [2] f3 f9 [2] f1 f8 [2] ea fe [2] f6 f9 [2] ea d6 }

  condition:
    any of them
}