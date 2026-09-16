rule TTP_XOR_QUAD_CurrentVersionRun_845c {
  strings:
    $key_845c = { d7 33 [2] f3 3d [2] d8 11 [2] f6 33 [2] e2 28 [2] ed 32 [2] f3 2f [2] f1 2e [2] ea 28 [2] f6 2f [2] ea 00 }

  condition:
    any of them
}