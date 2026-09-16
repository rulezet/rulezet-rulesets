rule TTP_XOR_QUAD_CurrentVersionRun_84f3 {
  strings:
    $key_84f3 = { d7 9c [2] f3 92 [2] d8 be [2] f6 9c [2] e2 87 [2] ed 9d [2] f3 80 [2] f1 81 [2] ea 87 [2] f6 80 [2] ea af }

  condition:
    any of them
}