rule TTP_XOR_QUAD_CurrentVersionRun_8596 {
  strings:
    $key_8596 = { d6 f9 [2] f2 f7 [2] d9 db [2] f7 f9 [2] e3 e2 [2] ec f8 [2] f2 e5 [2] f0 e4 [2] eb e2 [2] f7 e5 [2] eb ca }

  condition:
    any of them
}