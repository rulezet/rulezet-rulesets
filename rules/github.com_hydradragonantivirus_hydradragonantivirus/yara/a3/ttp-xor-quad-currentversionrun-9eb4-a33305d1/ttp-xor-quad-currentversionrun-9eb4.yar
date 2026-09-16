rule TTP_XOR_QUAD_CurrentVersionRun_9eb4 {
  strings:
    $key_9eb4 = { cd db [2] e9 d5 [2] c2 f9 [2] ec db [2] f8 c0 [2] f7 da [2] e9 c7 [2] eb c6 [2] f0 c0 [2] ec c7 [2] f0 e8 }

  condition:
    any of them
}