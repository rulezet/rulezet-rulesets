rule TTP_XOR_QUAD_CurrentVersionRun_83fc {
  strings:
    $key_83fc = { d0 93 [2] f4 9d [2] df b1 [2] f1 93 [2] e5 88 [2] ea 92 [2] f4 8f [2] f6 8e [2] ed 88 [2] f1 8f [2] ed a0 }

  condition:
    any of them
}