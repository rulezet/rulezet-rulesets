rule TTP_XOR_QUAD_CurrentVersionRun_8544 {
  strings:
    $key_8544 = { d6 2b [2] f2 25 [2] d9 09 [2] f7 2b [2] e3 30 [2] ec 2a [2] f2 37 [2] f0 36 [2] eb 30 [2] f7 37 [2] eb 18 }

  condition:
    any of them
}