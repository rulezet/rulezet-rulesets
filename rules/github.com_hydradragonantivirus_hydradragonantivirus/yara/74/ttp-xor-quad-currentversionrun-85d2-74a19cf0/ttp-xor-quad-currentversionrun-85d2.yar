rule TTP_XOR_QUAD_CurrentVersionRun_85d2 {
  strings:
    $key_85d2 = { d6 bd [2] f2 b3 [2] d9 9f [2] f7 bd [2] e3 a6 [2] ec bc [2] f2 a1 [2] f0 a0 [2] eb a6 [2] f7 a1 [2] eb 8e }

  condition:
    any of them
}