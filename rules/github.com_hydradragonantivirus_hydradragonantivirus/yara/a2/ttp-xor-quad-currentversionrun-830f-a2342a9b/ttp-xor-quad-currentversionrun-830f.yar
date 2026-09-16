rule TTP_XOR_QUAD_CurrentVersionRun_830f {
  strings:
    $key_830f = { d0 60 [2] f4 6e [2] df 42 [2] f1 60 [2] e5 7b [2] ea 61 [2] f4 7c [2] f6 7d [2] ed 7b [2] f1 7c [2] ed 53 }

  condition:
    any of them
}