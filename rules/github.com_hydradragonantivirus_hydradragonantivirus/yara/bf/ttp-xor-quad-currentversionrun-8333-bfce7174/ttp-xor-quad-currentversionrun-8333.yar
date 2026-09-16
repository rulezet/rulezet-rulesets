rule TTP_XOR_QUAD_CurrentVersionRun_8333 {
  strings:
    $key_8333 = { d0 5c [2] f4 52 [2] df 7e [2] f1 5c [2] e5 47 [2] ea 5d [2] f4 40 [2] f6 41 [2] ed 47 [2] f1 40 [2] ed 6f }

  condition:
    any of them
}