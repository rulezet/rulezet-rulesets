rule TTP_XOR_QUAD_CurrentVersionRun_8382 {
  strings:
    $key_8382 = { d0 ed [2] f4 e3 [2] df cf [2] f1 ed [2] e5 f6 [2] ea ec [2] f4 f1 [2] f6 f0 [2] ed f6 [2] f1 f1 [2] ed de }

  condition:
    any of them
}