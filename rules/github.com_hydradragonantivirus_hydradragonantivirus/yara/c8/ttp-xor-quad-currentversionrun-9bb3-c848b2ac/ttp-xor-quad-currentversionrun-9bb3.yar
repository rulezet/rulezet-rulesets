rule TTP_XOR_QUAD_CurrentVersionRun_9bb3 {
  strings:
    $key_9bb3 = { c8 dc [2] ec d2 [2] c7 fe [2] e9 dc [2] fd c7 [2] f2 dd [2] ec c0 [2] ee c1 [2] f5 c7 [2] e9 c0 [2] f5 ef }

  condition:
    any of them
}