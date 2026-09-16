rule TTP_XOR_QUAD_CurrentVersionRun_837d {
  strings:
    $key_837d = { d0 12 [2] f4 1c [2] df 30 [2] f1 12 [2] e5 09 [2] ea 13 [2] f4 0e [2] f6 0f [2] ed 09 [2] f1 0e [2] ed 21 }

  condition:
    any of them
}