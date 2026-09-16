rule TTP_XOR_QUAD_CurrentVersionRun_836d {
  strings:
    $key_836d = { d0 02 [2] f4 0c [2] df 20 [2] f1 02 [2] e5 19 [2] ea 03 [2] f4 1e [2] f6 1f [2] ed 19 [2] f1 1e [2] ed 31 }

  condition:
    any of them
}