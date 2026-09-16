rule TTP_XOR_QUAD_CurrentVersionRun_8440 {
  strings:
    $key_8440 = { d7 2f [2] f3 21 [2] d8 0d [2] f6 2f [2] e2 34 [2] ed 2e [2] f3 33 [2] f1 32 [2] ea 34 [2] f6 33 [2] ea 1c }

  condition:
    any of them
}