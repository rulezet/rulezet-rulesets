rule TTP_XOR_QUAD_CurrentVersionRun_8bdd {
  strings:
    $key_8bdd = { d8 b2 [2] fc bc [2] d7 90 [2] f9 b2 [2] ed a9 [2] e2 b3 [2] fc ae [2] fe af [2] e5 a9 [2] f9 ae [2] e5 81 }

  condition:
    any of them
}