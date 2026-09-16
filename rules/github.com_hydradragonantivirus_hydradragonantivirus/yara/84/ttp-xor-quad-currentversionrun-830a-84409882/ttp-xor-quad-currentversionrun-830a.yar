rule TTP_XOR_QUAD_CurrentVersionRun_830a {
  strings:
    $key_830a = { d0 65 [2] f4 6b [2] df 47 [2] f1 65 [2] e5 7e [2] ea 64 [2] f4 79 [2] f6 78 [2] ed 7e [2] f1 79 [2] ed 56 }

  condition:
    any of them
}