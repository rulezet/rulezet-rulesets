rule TTP_XOR_QUAD_CurrentVersionRun_835f {
  strings:
    $key_835f = { d0 30 [2] f4 3e [2] df 12 [2] f1 30 [2] e5 2b [2] ea 31 [2] f4 2c [2] f6 2d [2] ed 2b [2] f1 2c [2] ed 03 }

  condition:
    any of them
}