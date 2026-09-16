rule TTP_XOR_QUAD_CurrentVersionRun_83f6 {
  strings:
    $key_83f6 = { d0 99 [2] f4 97 [2] df bb [2] f1 99 [2] e5 82 [2] ea 98 [2] f4 85 [2] f6 84 [2] ed 82 [2] f1 85 [2] ed aa }

  condition:
    any of them
}