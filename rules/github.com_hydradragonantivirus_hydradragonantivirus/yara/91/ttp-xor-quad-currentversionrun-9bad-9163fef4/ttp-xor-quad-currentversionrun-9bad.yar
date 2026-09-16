rule TTP_XOR_QUAD_CurrentVersionRun_9bad {
  strings:
    $key_9bad = { c8 c2 [2] ec cc [2] c7 e0 [2] e9 c2 [2] fd d9 [2] f2 c3 [2] ec de [2] ee df [2] f5 d9 [2] e9 de [2] f5 f1 }

  condition:
    any of them
}