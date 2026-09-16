rule TTP_XOR_QUAD_CurrentVersionRun_85d1 {
  strings:
    $key_85d1 = { d6 be [2] f2 b0 [2] d9 9c [2] f7 be [2] e3 a5 [2] ec bf [2] f2 a2 [2] f0 a3 [2] eb a5 [2] f7 a2 [2] eb 8d }

  condition:
    any of them
}