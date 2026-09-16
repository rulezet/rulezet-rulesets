rule TTP_XOR_QUAD_CurrentVersionRun_832d {
  strings:
    $key_832d = { d0 42 [2] f4 4c [2] df 60 [2] f1 42 [2] e5 59 [2] ea 43 [2] f4 5e [2] f6 5f [2] ed 59 [2] f1 5e [2] ed 71 }

  condition:
    any of them
}