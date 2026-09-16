rule TTP_XOR_QUAD_CurrentVersionRun_8456 {
  strings:
    $key_8456 = { d7 39 [2] f3 37 [2] d8 1b [2] f6 39 [2] e2 22 [2] ed 38 [2] f3 25 [2] f1 24 [2] ea 22 [2] f6 25 [2] ea 0a }

  condition:
    any of them
}