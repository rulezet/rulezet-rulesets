rule TTP_XOR_QUAD_CurrentVersionRun_8401 {
  strings:
    $key_8401 = { d7 6e [2] f3 60 [2] d8 4c [2] f6 6e [2] e2 75 [2] ed 6f [2] f3 72 [2] f1 73 [2] ea 75 [2] f6 72 [2] ea 5d }

  condition:
    any of them
}