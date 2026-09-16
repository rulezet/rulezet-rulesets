rule TTP_XOR_QUAD_CurrentVersionRun_9bb1 {
  strings:
    $key_9bb1 = { c8 de [2] ec d0 [2] c7 fc [2] e9 de [2] fd c5 [2] f2 df [2] ec c2 [2] ee c3 [2] f5 c5 [2] e9 c2 [2] f5 ed }

  condition:
    any of them
}