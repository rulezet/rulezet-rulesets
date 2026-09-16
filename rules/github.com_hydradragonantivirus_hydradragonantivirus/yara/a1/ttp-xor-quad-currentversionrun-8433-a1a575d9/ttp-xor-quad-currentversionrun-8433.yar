rule TTP_XOR_QUAD_CurrentVersionRun_8433 {
  strings:
    $key_8433 = { d7 5c [2] f3 52 [2] d8 7e [2] f6 5c [2] e2 47 [2] ed 5d [2] f3 40 [2] f1 41 [2] ea 47 [2] f6 40 [2] ea 6f }

  condition:
    any of them
}