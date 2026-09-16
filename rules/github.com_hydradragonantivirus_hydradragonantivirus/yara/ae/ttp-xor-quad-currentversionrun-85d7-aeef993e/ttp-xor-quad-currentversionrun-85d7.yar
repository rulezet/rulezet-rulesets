rule TTP_XOR_QUAD_CurrentVersionRun_85d7 {
  strings:
    $key_85d7 = { d6 b8 [2] f2 b6 [2] d9 9a [2] f7 b8 [2] e3 a3 [2] ec b9 [2] f2 a4 [2] f0 a5 [2] eb a3 [2] f7 a4 [2] eb 8b }

  condition:
    any of them
}