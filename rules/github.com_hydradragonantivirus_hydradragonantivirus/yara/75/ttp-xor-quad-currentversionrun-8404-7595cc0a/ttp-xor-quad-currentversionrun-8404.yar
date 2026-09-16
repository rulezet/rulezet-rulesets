rule TTP_XOR_QUAD_CurrentVersionRun_8404 {
  strings:
    $key_8404 = { d7 6b [2] f3 65 [2] d8 49 [2] f6 6b [2] e2 70 [2] ed 6a [2] f3 77 [2] f1 76 [2] ea 70 [2] f6 77 [2] ea 58 }

  condition:
    any of them
}