rule TTP_XOR_QUAD_CurrentVersionRun_9e93 {
  strings:
    $key_9e93 = { cd fc [2] e9 f2 [2] c2 de [2] ec fc [2] f8 e7 [2] f7 fd [2] e9 e0 [2] eb e1 [2] f0 e7 [2] ec e0 [2] f0 cf }

  condition:
    any of them
}