rule TTP_XOR_QUAD_CurrentVersionRun_84f4 {
  strings:
    $key_84f4 = { d7 9b [2] f3 95 [2] d8 b9 [2] f6 9b [2] e2 80 [2] ed 9a [2] f3 87 [2] f1 86 [2] ea 80 [2] f6 87 [2] ea a8 }

  condition:
    any of them
}