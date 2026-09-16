rule TTP_XOR_QUAD_CurrentVersionRun_83fa {
  strings:
    $key_83fa = { d0 95 [2] f4 9b [2] df b7 [2] f1 95 [2] e5 8e [2] ea 94 [2] f4 89 [2] f6 88 [2] ed 8e [2] f1 89 [2] ed a6 }

  condition:
    any of them
}