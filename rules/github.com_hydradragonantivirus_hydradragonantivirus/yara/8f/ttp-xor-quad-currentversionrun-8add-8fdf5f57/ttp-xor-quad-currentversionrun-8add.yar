rule TTP_XOR_QUAD_CurrentVersionRun_8add {
  strings:
    $key_8add = { d9 b2 [2] fd bc [2] d6 90 [2] f8 b2 [2] ec a9 [2] e3 b3 [2] fd ae [2] ff af [2] e4 a9 [2] f8 ae [2] e4 81 }

  condition:
    any of them
}