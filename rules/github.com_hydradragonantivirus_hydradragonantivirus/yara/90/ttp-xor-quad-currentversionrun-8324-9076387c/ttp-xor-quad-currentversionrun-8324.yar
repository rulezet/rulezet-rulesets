rule TTP_XOR_QUAD_CurrentVersionRun_8324 {
  strings:
    $key_8324 = { d0 4b [2] f4 45 [2] df 69 [2] f1 4b [2] e5 50 [2] ea 4a [2] f4 57 [2] f6 56 [2] ed 50 [2] f1 57 [2] ed 78 }

  condition:
    any of them
}