rule TTP_XOR_QUAD_CurrentVersionRun_836c {
  strings:
    $key_836c = { d0 03 [2] f4 0d [2] df 21 [2] f1 03 [2] e5 18 [2] ea 02 [2] f4 1f [2] f6 1e [2] ed 18 [2] f1 1f [2] ed 30 }

  condition:
    any of them
}