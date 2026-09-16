rule TTP_XOR_QUAD_CurrentVersionRun_8415 {
  strings:
    $key_8415 = { d7 7a [2] f3 74 [2] d8 58 [2] f6 7a [2] e2 61 [2] ed 7b [2] f3 66 [2] f1 67 [2] ea 61 [2] f6 66 [2] ea 49 }

  condition:
    any of them
}