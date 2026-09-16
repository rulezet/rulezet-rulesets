rule TTP_XOR_QUAD_CurrentVersionRun_8467 {
  strings:
    $key_8467 = { d7 08 [2] f3 06 [2] d8 2a [2] f6 08 [2] e2 13 [2] ed 09 [2] f3 14 [2] f1 15 [2] ea 13 [2] f6 14 [2] ea 3b }

  condition:
    any of them
}