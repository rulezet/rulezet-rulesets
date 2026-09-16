rule TTP_XOR_QUAD_CurrentVersionRun_9ba6 {
  strings:
    $key_9ba6 = { c8 c9 [2] ec c7 [2] c7 eb [2] e9 c9 [2] fd d2 [2] f2 c8 [2] ec d5 [2] ee d4 [2] f5 d2 [2] e9 d5 [2] f5 fa }

  condition:
    any of them
}