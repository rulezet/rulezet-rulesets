rule TTP_XOR_QUAD_CurrentVersionRun_9bb6 {
  strings:
    $key_9bb6 = { c8 d9 [2] ec d7 [2] c7 fb [2] e9 d9 [2] fd c2 [2] f2 d8 [2] ec c5 [2] ee c4 [2] f5 c2 [2] e9 c5 [2] f5 ea }

  condition:
    any of them
}