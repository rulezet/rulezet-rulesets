rule TTP_XOR_QUAD_CurrentVersionRun_84ec {
  strings:
    $key_84ec = { d7 83 [2] f3 8d [2] d8 a1 [2] f6 83 [2] e2 98 [2] ed 82 [2] f3 9f [2] f1 9e [2] ea 98 [2] f6 9f [2] ea b0 }

  condition:
    any of them
}