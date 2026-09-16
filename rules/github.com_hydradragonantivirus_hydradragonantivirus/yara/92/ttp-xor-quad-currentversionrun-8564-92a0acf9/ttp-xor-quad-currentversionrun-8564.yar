rule TTP_XOR_QUAD_CurrentVersionRun_8564 {
  strings:
    $key_8564 = { d6 0b [2] f2 05 [2] d9 29 [2] f7 0b [2] e3 10 [2] ec 0a [2] f2 17 [2] f0 16 [2] eb 10 [2] f7 17 [2] eb 38 }

  condition:
    any of them
}