rule TTP_XOR_QUAD_CurrentVersionRun_84fb {
  strings:
    $key_84fb = { d7 94 [2] f3 9a [2] d8 b6 [2] f6 94 [2] e2 8f [2] ed 95 [2] f3 88 [2] f1 89 [2] ea 8f [2] f6 88 [2] ea a7 }

  condition:
    any of them
}