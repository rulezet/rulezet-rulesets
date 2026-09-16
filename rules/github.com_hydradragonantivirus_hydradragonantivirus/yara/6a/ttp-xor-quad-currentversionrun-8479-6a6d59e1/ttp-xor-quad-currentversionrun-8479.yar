rule TTP_XOR_QUAD_CurrentVersionRun_8479 {
  strings:
    $key_8479 = { d7 16 [2] f3 18 [2] d8 34 [2] f6 16 [2] e2 0d [2] ed 17 [2] f3 0a [2] f1 0b [2] ea 0d [2] f6 0a [2] ea 25 }

  condition:
    any of them
}