rule TTP_XOR_QUAD_CurrentVersionRun_83eb {
  strings:
    $key_83eb = { d0 84 [2] f4 8a [2] df a6 [2] f1 84 [2] e5 9f [2] ea 85 [2] f4 98 [2] f6 99 [2] ed 9f [2] f1 98 [2] ed b7 }

  condition:
    any of them
}