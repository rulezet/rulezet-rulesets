rule TTP_XOR_QUAD_CurrentVersionRun_84e7 {
  strings:
    $key_84e7 = { d7 88 [2] f3 86 [2] d8 aa [2] f6 88 [2] e2 93 [2] ed 89 [2] f3 94 [2] f1 95 [2] ea 93 [2] f6 94 [2] ea bb }

  condition:
    any of them
}