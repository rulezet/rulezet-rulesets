rule TTP_XOR_QUAD_CurrentVersionRun_83f7 {
  strings:
    $key_83f7 = { d0 98 [2] f4 96 [2] df ba [2] f1 98 [2] e5 83 [2] ea 99 [2] f4 84 [2] f6 85 [2] ed 83 [2] f1 84 [2] ed ab }

  condition:
    any of them
}