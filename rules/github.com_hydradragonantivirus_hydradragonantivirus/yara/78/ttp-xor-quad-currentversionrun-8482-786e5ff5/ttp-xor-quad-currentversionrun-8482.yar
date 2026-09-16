rule TTP_XOR_QUAD_CurrentVersionRun_8482 {
  strings:
    $key_8482 = { d7 ed [2] f3 e3 [2] d8 cf [2] f6 ed [2] e2 f6 [2] ed ec [2] f3 f1 [2] f1 f0 [2] ea f6 [2] f6 f1 [2] ea de }

  condition:
    any of them
}