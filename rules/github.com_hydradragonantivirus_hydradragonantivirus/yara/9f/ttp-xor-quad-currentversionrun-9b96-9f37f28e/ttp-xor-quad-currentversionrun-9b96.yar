rule TTP_XOR_QUAD_CurrentVersionRun_9b96 {
  strings:
    $key_9b96 = { c8 f9 [2] ec f7 [2] c7 db [2] e9 f9 [2] fd e2 [2] f2 f8 [2] ec e5 [2] ee e4 [2] f5 e2 [2] e9 e5 [2] f5 ca }

  condition:
    any of them
}