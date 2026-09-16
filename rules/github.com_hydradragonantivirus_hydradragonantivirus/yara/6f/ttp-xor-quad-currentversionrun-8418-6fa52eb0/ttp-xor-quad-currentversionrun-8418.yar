rule TTP_XOR_QUAD_CurrentVersionRun_8418 {
  strings:
    $key_8418 = { d7 77 [2] f3 79 [2] d8 55 [2] f6 77 [2] e2 6c [2] ed 76 [2] f3 6b [2] f1 6a [2] ea 6c [2] f6 6b [2] ea 44 }

  condition:
    any of them
}