rule TTP_XOR_QUAD_CurrentVersionRun_8307 {
  strings:
    $key_8307 = { d0 68 [2] f4 66 [2] df 4a [2] f1 68 [2] e5 73 [2] ea 69 [2] f4 74 [2] f6 75 [2] ed 73 [2] f1 74 [2] ed 5b }

  condition:
    any of them
}