rule TTP_XOR_QUAD_CurrentVersionRun_834b {
  strings:
    $key_834b = { d0 24 [2] f4 2a [2] df 06 [2] f1 24 [2] e5 3f [2] ea 25 [2] f4 38 [2] f6 39 [2] ed 3f [2] f1 38 [2] ed 17 }

  condition:
    any of them
}