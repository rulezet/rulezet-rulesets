rule TTP_XOR_QUAD_CurrentVersionRun_8548 {
  strings:
    $key_8548 = { d6 27 [2] f2 29 [2] d9 05 [2] f7 27 [2] e3 3c [2] ec 26 [2] f2 3b [2] f0 3a [2] eb 3c [2] f7 3b [2] eb 14 }

  condition:
    any of them
}