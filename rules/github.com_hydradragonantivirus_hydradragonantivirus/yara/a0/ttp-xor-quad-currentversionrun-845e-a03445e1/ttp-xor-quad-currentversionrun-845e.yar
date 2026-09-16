rule TTP_XOR_QUAD_CurrentVersionRun_845e {
  strings:
    $key_845e = { d7 31 [2] f3 3f [2] d8 13 [2] f6 31 [2] e2 2a [2] ed 30 [2] f3 2d [2] f1 2c [2] ea 2a [2] f6 2d [2] ea 02 }

  condition:
    any of them
}