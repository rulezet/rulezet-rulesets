rule TTP_XOR_QUAD_CurrentVersionRun_8468 {
  strings:
    $key_8468 = { d7 07 [2] f3 09 [2] d8 25 [2] f6 07 [2] e2 1c [2] ed 06 [2] f3 1b [2] f1 1a [2] ea 1c [2] f6 1b [2] ea 34 }

  condition:
    any of them
}