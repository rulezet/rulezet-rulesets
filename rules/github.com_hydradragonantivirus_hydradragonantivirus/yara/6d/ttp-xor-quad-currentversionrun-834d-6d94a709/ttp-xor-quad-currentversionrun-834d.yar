rule TTP_XOR_QUAD_CurrentVersionRun_834d {
  strings:
    $key_834d = { d0 22 [2] f4 2c [2] df 00 [2] f1 22 [2] e5 39 [2] ea 23 [2] f4 3e [2] f6 3f [2] ed 39 [2] f1 3e [2] ed 11 }

  condition:
    any of them
}