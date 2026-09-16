rule TTP_XOR_QUAD_CurrentVersionRun_8315 {
  strings:
    $key_8315 = { d0 7a [2] f4 74 [2] df 58 [2] f1 7a [2] e5 61 [2] ea 7b [2] f4 66 [2] f6 67 [2] ed 61 [2] f1 66 [2] ed 49 }

  condition:
    any of them
}