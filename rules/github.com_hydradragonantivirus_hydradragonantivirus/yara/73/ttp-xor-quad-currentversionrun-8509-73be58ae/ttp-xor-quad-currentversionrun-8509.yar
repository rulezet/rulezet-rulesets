rule TTP_XOR_QUAD_CurrentVersionRun_8509 {
  strings:
    $key_8509 = { d6 66 [2] f2 68 [2] d9 44 [2] f7 66 [2] e3 7d [2] ec 67 [2] f2 7a [2] f0 7b [2] eb 7d [2] f7 7a [2] eb 55 }

  condition:
    any of them
}