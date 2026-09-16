rule TTP_XOR_QUAD_CurrentVersionRun_8407 {
  strings:
    $key_8407 = { d7 68 [2] f3 66 [2] d8 4a [2] f6 68 [2] e2 73 [2] ed 69 [2] f3 74 [2] f1 75 [2] ea 73 [2] f6 74 [2] ea 5b }

  condition:
    any of them
}