rule TTP_XOR_QUAD_CurrentVersionRun_9b82 {
  strings:
    $key_9b82 = { c8 ed [2] ec e3 [2] c7 cf [2] e9 ed [2] fd f6 [2] f2 ec [2] ec f1 [2] ee f0 [2] f5 f6 [2] e9 f1 [2] f5 de }

  condition:
    any of them
}