rule TTP_XOR_QUAD_CurrentVersionRun_9b86 {
  strings:
    $key_9b86 = { c8 e9 [2] ec e7 [2] c7 cb [2] e9 e9 [2] fd f2 [2] f2 e8 [2] ec f5 [2] ee f4 [2] f5 f2 [2] e9 f5 [2] f5 da }

  condition:
    any of them
}