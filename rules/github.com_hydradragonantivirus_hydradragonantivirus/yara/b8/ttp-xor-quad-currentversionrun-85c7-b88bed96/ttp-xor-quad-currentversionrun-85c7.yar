rule TTP_XOR_QUAD_CurrentVersionRun_85c7 {
  strings:
    $key_85c7 = { d6 a8 [2] f2 a6 [2] d9 8a [2] f7 a8 [2] e3 b3 [2] ec a9 [2] f2 b4 [2] f0 b5 [2] eb b3 [2] f7 b4 [2] eb 9b }

  condition:
    any of them
}