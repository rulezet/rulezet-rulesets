rule TTP_XOR_QUAD_CurrentVersionRun_8455 {
  strings:
    $key_8455 = { d7 3a [2] f3 34 [2] d8 18 [2] f6 3a [2] e2 21 [2] ed 3b [2] f3 26 [2] f1 27 [2] ea 21 [2] f6 26 [2] ea 09 }

  condition:
    any of them
}