rule TTP_XOR_QUAD_CurrentVersionRun_84f8 {
  strings:
    $key_84f8 = { d7 97 [2] f3 99 [2] d8 b5 [2] f6 97 [2] e2 8c [2] ed 96 [2] f3 8b [2] f1 8a [2] ea 8c [2] f6 8b [2] ea a4 }

  condition:
    any of them
}