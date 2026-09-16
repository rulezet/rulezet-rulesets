rule TTP_XOR_QUAD_CurrentVersionRun_831a {
  strings:
    $key_831a = { d0 75 [2] f4 7b [2] df 57 [2] f1 75 [2] e5 6e [2] ea 74 [2] f4 69 [2] f6 68 [2] ed 6e [2] f1 69 [2] ed 46 }

  condition:
    any of them
}