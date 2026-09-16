rule TTP_XOR_QUAD_CurrentVersionRun_85e4 {
  strings:
    $key_85e4 = { d6 8b [2] f2 85 [2] d9 a9 [2] f7 8b [2] e3 90 [2] ec 8a [2] f2 97 [2] f0 96 [2] eb 90 [2] f7 97 [2] eb b8 }

  condition:
    any of them
}