rule TTP_XOR_QUAD_CurrentVersionRun_8406 {
  strings:
    $key_8406 = { d7 69 [2] f3 67 [2] d8 4b [2] f6 69 [2] e2 72 [2] ed 68 [2] f3 75 [2] f1 74 [2] ea 72 [2] f6 75 [2] ea 5a }

  condition:
    any of them
}