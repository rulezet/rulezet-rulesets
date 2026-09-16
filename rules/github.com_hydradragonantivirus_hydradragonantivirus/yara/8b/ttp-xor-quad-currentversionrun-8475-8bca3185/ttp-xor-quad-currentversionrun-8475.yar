rule TTP_XOR_QUAD_CurrentVersionRun_8475 {
  strings:
    $key_8475 = { d7 1a [2] f3 14 [2] d8 38 [2] f6 1a [2] e2 01 [2] ed 1b [2] f3 06 [2] f1 07 [2] ea 01 [2] f6 06 [2] ea 29 }

  condition:
    any of them
}