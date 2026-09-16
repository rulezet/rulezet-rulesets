rule TTP_XOR_QUAD_CurrentVersionRun_8329 {
  strings:
    $key_8329 = { d0 46 [2] f4 48 [2] df 64 [2] f1 46 [2] e5 5d [2] ea 47 [2] f4 5a [2] f6 5b [2] ed 5d [2] f1 5a [2] ed 75 }

  condition:
    any of them
}