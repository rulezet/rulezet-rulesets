rule TTP_XOR_QUAD_CurrentVersionRun_8483 {
  strings:
    $key_8483 = { d7 ec [2] f3 e2 [2] d8 ce [2] f6 ec [2] e2 f7 [2] ed ed [2] f3 f0 [2] f1 f1 [2] ea f7 [2] f6 f0 [2] ea df }

  condition:
    any of them
}