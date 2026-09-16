rule TTP_XOR_QUAD_CurrentVersionRun_831d {
  strings:
    $key_831d = { d0 72 [2] f4 7c [2] df 50 [2] f1 72 [2] e5 69 [2] ea 73 [2] f4 6e [2] f6 6f [2] ed 69 [2] f1 6e [2] ed 41 }

  condition:
    any of them
}