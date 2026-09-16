rule TTP_XOR_QUAD_CurrentVersionRun_8444 {
  strings:
    $key_8444 = { d7 2b [2] f3 25 [2] d8 09 [2] f6 2b [2] e2 30 [2] ed 2a [2] f3 37 [2] f1 36 [2] ea 30 [2] f6 37 [2] ea 18 }

  condition:
    any of them
}