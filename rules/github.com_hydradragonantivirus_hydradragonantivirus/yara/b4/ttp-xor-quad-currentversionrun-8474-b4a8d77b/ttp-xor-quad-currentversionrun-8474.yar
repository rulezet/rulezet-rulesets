rule TTP_XOR_QUAD_CurrentVersionRun_8474 {
  strings:
    $key_8474 = { d7 1b [2] f3 15 [2] d8 39 [2] f6 1b [2] e2 00 [2] ed 1a [2] f3 07 [2] f1 06 [2] ea 00 [2] f6 07 [2] ea 28 }

  condition:
    any of them
}