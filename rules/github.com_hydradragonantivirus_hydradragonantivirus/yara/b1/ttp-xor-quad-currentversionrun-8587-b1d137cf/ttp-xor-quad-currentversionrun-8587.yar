rule TTP_XOR_QUAD_CurrentVersionRun_8587 {
  strings:
    $key_8587 = { d6 e8 [2] f2 e6 [2] d9 ca [2] f7 e8 [2] e3 f3 [2] ec e9 [2] f2 f4 [2] f0 f5 [2] eb f3 [2] f7 f4 [2] eb db }

  condition:
    any of them
}