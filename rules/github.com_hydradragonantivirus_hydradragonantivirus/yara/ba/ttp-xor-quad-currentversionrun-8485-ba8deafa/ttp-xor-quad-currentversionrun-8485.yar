rule TTP_XOR_QUAD_CurrentVersionRun_8485 {
  strings:
    $key_8485 = { d7 ea [2] f3 e4 [2] d8 c8 [2] f6 ea [2] e2 f1 [2] ed eb [2] f3 f6 [2] f1 f7 [2] ea f1 [2] f6 f6 [2] ea d9 }

  condition:
    any of them
}