rule TTP_XOR_QUAD_CurrentVersionRun_83d7 {
  strings:
    $key_83d7 = { d0 b8 [2] f4 b6 [2] df 9a [2] f1 b8 [2] e5 a3 [2] ea b9 [2] f4 a4 [2] f6 a5 [2] ed a3 [2] f1 a4 [2] ed 8b }

  condition:
    any of them
}