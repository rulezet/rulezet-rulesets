rule TTP_XOR_QUAD_CurrentVersionRun_83c7 {
  strings:
    $key_83c7 = { d0 a8 [2] f4 a6 [2] df 8a [2] f1 a8 [2] e5 b3 [2] ea a9 [2] f4 b4 [2] f6 b5 [2] ed b3 [2] f1 b4 [2] ed 9b }

  condition:
    any of them
}