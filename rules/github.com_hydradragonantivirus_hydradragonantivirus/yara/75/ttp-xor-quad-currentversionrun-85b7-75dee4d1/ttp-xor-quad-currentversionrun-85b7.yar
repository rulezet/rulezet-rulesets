rule TTP_XOR_QUAD_CurrentVersionRun_85b7 {
  strings:
    $key_85b7 = { d6 d8 [2] f2 d6 [2] d9 fa [2] f7 d8 [2] e3 c3 [2] ec d9 [2] f2 c4 [2] f0 c5 [2] eb c3 [2] f7 c4 [2] eb eb }

  condition:
    any of them
}