rule TTP_XOR_QUAD_CurrentVersionRun_83f8 {
  strings:
    $key_83f8 = { d0 97 [2] f4 99 [2] df b5 [2] f1 97 [2] e5 8c [2] ea 96 [2] f4 8b [2] f6 8a [2] ed 8c [2] f1 8b [2] ed a4 }

  condition:
    any of them
}