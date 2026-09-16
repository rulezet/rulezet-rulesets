rule TTP_XOR_QUAD_CurrentVersionRun_83c6 {
  strings:
    $key_83c6 = { d0 a9 [2] f4 a7 [2] df 8b [2] f1 a9 [2] e5 b2 [2] ea a8 [2] f4 b5 [2] f6 b4 [2] ed b2 [2] f1 b5 [2] ed 9a }

  condition:
    any of them
}