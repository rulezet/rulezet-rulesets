rule TTP_XOR_QUAD_CurrentVersionRun_85c9 {
  strings:
    $key_85c9 = { d6 a6 [2] f2 a8 [2] d9 84 [2] f7 a6 [2] e3 bd [2] ec a7 [2] f2 ba [2] f0 bb [2] eb bd [2] f7 ba [2] eb 95 }

  condition:
    any of them
}