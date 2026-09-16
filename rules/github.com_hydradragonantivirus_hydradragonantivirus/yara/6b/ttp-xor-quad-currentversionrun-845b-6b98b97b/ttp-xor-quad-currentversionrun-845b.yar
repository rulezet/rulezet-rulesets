rule TTP_XOR_QUAD_CurrentVersionRun_845b {
  strings:
    $key_845b = { d7 34 [2] f3 3a [2] d8 16 [2] f6 34 [2] e2 2f [2] ed 35 [2] f3 28 [2] f1 29 [2] ea 2f [2] f6 28 [2] ea 07 }

  condition:
    any of them
}