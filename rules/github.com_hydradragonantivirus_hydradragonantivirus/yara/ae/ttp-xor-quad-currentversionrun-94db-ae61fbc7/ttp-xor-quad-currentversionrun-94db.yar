rule TTP_XOR_QUAD_CurrentVersionRun_94db {
  strings:
    $key_94db = { c7 b4 [2] e3 ba [2] c8 96 [2] e6 b4 [2] f2 af [2] fd b5 [2] e3 a8 [2] e1 a9 [2] fa af [2] e6 a8 [2] fa 87 }

  condition:
    any of them
}