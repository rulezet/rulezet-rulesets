rule TTP_XOR_QUAD_CurrentVersionRun_8ada {
  strings:
    $key_8ada = { d9 b5 [2] fd bb [2] d6 97 [2] f8 b5 [2] ec ae [2] e3 b4 [2] fd a9 [2] ff a8 [2] e4 ae [2] f8 a9 [2] e4 86 }

  condition:
    any of them
}