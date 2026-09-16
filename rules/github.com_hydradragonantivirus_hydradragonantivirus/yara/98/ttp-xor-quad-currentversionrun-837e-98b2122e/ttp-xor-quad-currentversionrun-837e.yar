rule TTP_XOR_QUAD_CurrentVersionRun_837e {
  strings:
    $key_837e = { d0 11 [2] f4 1f [2] df 33 [2] f1 11 [2] e5 0a [2] ea 10 [2] f4 0d [2] f6 0c [2] ed 0a [2] f1 0d [2] ed 22 }

  condition:
    any of them
}