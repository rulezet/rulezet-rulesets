rule TTP_XOR_QUAD_CurrentVersionRun_9b85 {
  strings:
    $key_9b85 = { c8 ea [2] ec e4 [2] c7 c8 [2] e9 ea [2] fd f1 [2] f2 eb [2] ec f6 [2] ee f7 [2] f5 f1 [2] e9 f6 [2] f5 d9 }

  condition:
    any of them
}