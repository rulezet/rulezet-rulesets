rule TTP_XOR_QUAD_CurrentVersionRun_8409 {
  strings:
    $key_8409 = { d7 66 [2] f3 68 [2] d8 44 [2] f6 66 [2] e2 7d [2] ed 67 [2] f3 7a [2] f1 7b [2] ea 7d [2] f6 7a [2] ea 55 }

  condition:
    any of them
}