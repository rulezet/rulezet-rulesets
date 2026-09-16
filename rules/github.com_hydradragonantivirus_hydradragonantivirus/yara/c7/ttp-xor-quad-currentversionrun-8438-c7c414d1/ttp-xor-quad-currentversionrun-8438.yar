rule TTP_XOR_QUAD_CurrentVersionRun_8438 {
  strings:
    $key_8438 = { d7 57 [2] f3 59 [2] d8 75 [2] f6 57 [2] e2 4c [2] ed 56 [2] f3 4b [2] f1 4a [2] ea 4c [2] f6 4b [2] ea 64 }

  condition:
    any of them
}