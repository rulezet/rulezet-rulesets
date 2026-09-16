rule TTP_XOR_QUAD_CurrentVersionRun_83e5 {
  strings:
    $key_83e5 = { d0 8a [2] f4 84 [2] df a8 [2] f1 8a [2] e5 91 [2] ea 8b [2] f4 96 [2] f6 97 [2] ed 91 [2] f1 96 [2] ed b9 }

  condition:
    any of them
}