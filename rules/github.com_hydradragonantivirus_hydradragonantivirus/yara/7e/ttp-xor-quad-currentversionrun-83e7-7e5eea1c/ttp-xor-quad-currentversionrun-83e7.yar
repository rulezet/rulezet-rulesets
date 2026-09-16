rule TTP_XOR_QUAD_CurrentVersionRun_83e7 {
  strings:
    $key_83e7 = { d0 88 [2] f4 86 [2] df aa [2] f1 88 [2] e5 93 [2] ea 89 [2] f4 94 [2] f6 95 [2] ed 93 [2] f1 94 [2] ed bb }

  condition:
    any of them
}