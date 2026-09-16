rule TTP_XOR_QUAD_CurrentVersionRun_8519 {
  strings:
    $key_8519 = { d6 76 [2] f2 78 [2] d9 54 [2] f7 76 [2] e3 6d [2] ec 77 [2] f2 6a [2] f0 6b [2] eb 6d [2] f7 6a [2] eb 45 }

  condition:
    any of them
}