rule TTP_XOR_QUAD_CurrentVersionRun_847b {
  strings:
    $key_847b = { d7 14 [2] f3 1a [2] d8 36 [2] f6 14 [2] e2 0f [2] ed 15 [2] f3 08 [2] f1 09 [2] ea 0f [2] f6 08 [2] ea 27 }

  condition:
    any of them
}