rule TTP_XOR_QUAD_CurrentVersionRun_84e5 {
  strings:
    $key_84e5 = { d7 8a [2] f3 84 [2] d8 a8 [2] f6 8a [2] e2 91 [2] ed 8b [2] f3 96 [2] f1 97 [2] ea 91 [2] f6 96 [2] ea b9 }

  condition:
    any of them
}