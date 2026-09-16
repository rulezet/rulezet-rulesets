rule TTP_XOR_QUAD_CurrentVersionRun_834c {
  strings:
    $key_834c = { d0 23 [2] f4 2d [2] df 01 [2] f1 23 [2] e5 38 [2] ea 22 [2] f4 3f [2] f6 3e [2] ed 38 [2] f1 3f [2] ed 10 }

  condition:
    any of them
}