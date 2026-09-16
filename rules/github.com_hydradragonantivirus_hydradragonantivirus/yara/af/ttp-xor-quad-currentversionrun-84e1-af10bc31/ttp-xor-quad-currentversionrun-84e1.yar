rule TTP_XOR_QUAD_CurrentVersionRun_84e1 {
  strings:
    $key_84e1 = { d7 8e [2] f3 80 [2] d8 ac [2] f6 8e [2] e2 95 [2] ed 8f [2] f3 92 [2] f1 93 [2] ea 95 [2] f6 92 [2] ea bd }

  condition:
    any of them
}