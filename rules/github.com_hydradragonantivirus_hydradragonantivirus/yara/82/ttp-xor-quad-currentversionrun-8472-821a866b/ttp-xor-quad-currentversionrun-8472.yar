rule TTP_XOR_QUAD_CurrentVersionRun_8472 {
  strings:
    $key_8472 = { d7 1d [2] f3 13 [2] d8 3f [2] f6 1d [2] e2 06 [2] ed 1c [2] f3 01 [2] f1 00 [2] ea 06 [2] f6 01 [2] ea 2e }

  condition:
    any of them
}