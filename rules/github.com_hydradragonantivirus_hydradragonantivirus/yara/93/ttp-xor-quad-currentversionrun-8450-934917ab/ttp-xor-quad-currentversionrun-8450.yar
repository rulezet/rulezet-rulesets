rule TTP_XOR_QUAD_CurrentVersionRun_8450 {
  strings:
    $key_8450 = { d7 3f [2] f3 31 [2] d8 1d [2] f6 3f [2] e2 24 [2] ed 3e [2] f3 23 [2] f1 22 [2] ea 24 [2] f6 23 [2] ea 0c }

  condition:
    any of them
}