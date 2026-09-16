rule TTP_XOR_QUAD_CurrentVersionRun_8445 {
  strings:
    $key_8445 = { d7 2a [2] f3 24 [2] d8 08 [2] f6 2a [2] e2 31 [2] ed 2b [2] f3 36 [2] f1 37 [2] ea 31 [2] f6 36 [2] ea 19 }

  condition:
    any of them
}