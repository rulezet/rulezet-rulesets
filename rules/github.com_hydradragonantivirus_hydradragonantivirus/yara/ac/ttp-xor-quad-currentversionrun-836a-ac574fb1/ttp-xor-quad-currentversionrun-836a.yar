rule TTP_XOR_QUAD_CurrentVersionRun_836a {
  strings:
    $key_836a = { d0 05 [2] f4 0b [2] df 27 [2] f1 05 [2] e5 1e [2] ea 04 [2] f4 19 [2] f6 18 [2] ed 1e [2] f1 19 [2] ed 36 }

  condition:
    any of them
}