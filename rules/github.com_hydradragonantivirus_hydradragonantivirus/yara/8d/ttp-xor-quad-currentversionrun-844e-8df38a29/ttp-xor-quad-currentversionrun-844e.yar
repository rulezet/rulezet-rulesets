rule TTP_XOR_QUAD_CurrentVersionRun_844e {
  strings:
    $key_844e = { d7 21 [2] f3 2f [2] d8 03 [2] f6 21 [2] e2 3a [2] ed 20 [2] f3 3d [2] f1 3c [2] ea 3a [2] f6 3d [2] ea 12 }

  condition:
    any of them
}