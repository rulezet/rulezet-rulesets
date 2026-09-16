rule TTP_XOR_QUAD_CurrentVersionRun_8464 {
  strings:
    $key_8464 = { d7 0b [2] f3 05 [2] d8 29 [2] f6 0b [2] e2 10 [2] ed 0a [2] f3 17 [2] f1 16 [2] ea 10 [2] f6 17 [2] ea 38 }

  condition:
    any of them
}