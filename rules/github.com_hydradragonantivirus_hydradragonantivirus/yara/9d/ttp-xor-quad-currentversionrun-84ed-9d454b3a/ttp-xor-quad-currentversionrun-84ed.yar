rule TTP_XOR_QUAD_CurrentVersionRun_84ed {
  strings:
    $key_84ed = { d7 82 [2] f3 8c [2] d8 a0 [2] f6 82 [2] e2 99 [2] ed 83 [2] f3 9e [2] f1 9f [2] ea 99 [2] f6 9e [2] ea b1 }

  condition:
    any of them
}