rule TTP_XOR_QUAD_CurrentVersionRun_836f {
  strings:
    $key_836f = { d0 00 [2] f4 0e [2] df 22 [2] f1 00 [2] e5 1b [2] ea 01 [2] f4 1c [2] f6 1d [2] ed 1b [2] f1 1c [2] ed 33 }

  condition:
    any of them
}