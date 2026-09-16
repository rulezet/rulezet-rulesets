rule TTP_XOR_QUAD_CurrentVersionRun_835e {
  strings:
    $key_835e = { d0 31 [2] f4 3f [2] df 13 [2] f1 31 [2] e5 2a [2] ea 30 [2] f4 2d [2] f6 2c [2] ed 2a [2] f1 2d [2] ed 02 }

  condition:
    any of them
}