rule TTP_XOR_QUAD_CurrentVersionRun_837b {
  strings:
    $key_837b = { d0 14 [2] f4 1a [2] df 36 [2] f1 14 [2] e5 0f [2] ea 15 [2] f4 08 [2] f6 09 [2] ed 0f [2] f1 08 [2] ed 27 }

  condition:
    any of them
}