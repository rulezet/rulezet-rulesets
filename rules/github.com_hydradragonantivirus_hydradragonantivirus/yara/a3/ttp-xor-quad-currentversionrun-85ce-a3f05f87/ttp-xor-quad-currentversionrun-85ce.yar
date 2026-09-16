rule TTP_XOR_QUAD_CurrentVersionRun_85ce {
  strings:
    $key_85ce = { d6 a1 [2] f2 af [2] d9 83 [2] f7 a1 [2] e3 ba [2] ec a0 [2] f2 bd [2] f0 bc [2] eb ba [2] f7 bd [2] eb 92 }

  condition:
    any of them
}