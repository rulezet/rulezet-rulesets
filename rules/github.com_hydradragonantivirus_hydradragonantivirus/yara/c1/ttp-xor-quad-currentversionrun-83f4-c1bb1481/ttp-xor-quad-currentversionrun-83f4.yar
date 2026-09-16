rule TTP_XOR_QUAD_CurrentVersionRun_83f4 {
  strings:
    $key_83f4 = { d0 9b [2] f4 95 [2] df b9 [2] f1 9b [2] e5 80 [2] ea 9a [2] f4 87 [2] f6 86 [2] ed 80 [2] f1 87 [2] ed a8 }

  condition:
    any of them
}