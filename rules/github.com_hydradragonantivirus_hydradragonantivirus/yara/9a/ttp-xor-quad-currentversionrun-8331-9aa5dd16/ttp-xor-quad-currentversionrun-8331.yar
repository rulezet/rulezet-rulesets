rule TTP_XOR_QUAD_CurrentVersionRun_8331 {
  strings:
    $key_8331 = { d0 5e [2] f4 50 [2] df 7c [2] f1 5e [2] e5 45 [2] ea 5f [2] f4 42 [2] f6 43 [2] ed 45 [2] f1 42 [2] ed 6d }

  condition:
    any of them
}