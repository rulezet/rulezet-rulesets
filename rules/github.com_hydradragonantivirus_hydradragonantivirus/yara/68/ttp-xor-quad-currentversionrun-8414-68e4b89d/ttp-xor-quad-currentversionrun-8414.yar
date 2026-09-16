rule TTP_XOR_QUAD_CurrentVersionRun_8414 {
  strings:
    $key_8414 = { d7 7b [2] f3 75 [2] d8 59 [2] f6 7b [2] e2 60 [2] ed 7a [2] f3 67 [2] f1 66 [2] ea 60 [2] f6 67 [2] ea 48 }

  condition:
    any of them
}