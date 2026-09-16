rule TTP_XOR_QUAD_CurrentVersionRun_8535 {
  strings:
    $key_8535 = { d6 5a [2] f2 54 [2] d9 78 [2] f7 5a [2] e3 41 [2] ec 5b [2] f2 46 [2] f0 47 [2] eb 41 [2] f7 46 [2] eb 69 }

  condition:
    any of them
}