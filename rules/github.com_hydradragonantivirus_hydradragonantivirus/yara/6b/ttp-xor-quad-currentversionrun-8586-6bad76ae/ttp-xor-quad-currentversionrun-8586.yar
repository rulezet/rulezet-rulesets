rule TTP_XOR_QUAD_CurrentVersionRun_8586 {
  strings:
    $key_8586 = { d6 e9 [2] f2 e7 [2] d9 cb [2] f7 e9 [2] e3 f2 [2] ec e8 [2] f2 f5 [2] f0 f4 [2] eb f2 [2] f7 f5 [2] eb da }

  condition:
    any of them
}