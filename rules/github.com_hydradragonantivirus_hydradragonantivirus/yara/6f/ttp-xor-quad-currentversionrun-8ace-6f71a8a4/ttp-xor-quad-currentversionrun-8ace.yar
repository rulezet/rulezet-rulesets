rule TTP_XOR_QUAD_CurrentVersionRun_8ace {
  strings:
    $key_8ace = { d9 a1 [2] fd af [2] d6 83 [2] f8 a1 [2] ec ba [2] e3 a0 [2] fd bd [2] ff bc [2] e4 ba [2] f8 bd [2] e4 92 }

  condition:
    any of them
}