rule TTP_XOR_QUAD_CurrentVersionRun_8449 {
  strings:
    $key_8449 = { d7 26 [2] f3 28 [2] d8 04 [2] f6 26 [2] e2 3d [2] ed 27 [2] f3 3a [2] f1 3b [2] ea 3d [2] f6 3a [2] ea 15 }

  condition:
    any of them
}