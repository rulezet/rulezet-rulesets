rule TTP_XOR_QUAD_CurrentVersionRun_85e8 {
  strings:
    $key_85e8 = { d6 87 [2] f2 89 [2] d9 a5 [2] f7 87 [2] e3 9c [2] ec 86 [2] f2 9b [2] f0 9a [2] eb 9c [2] f7 9b [2] eb b4 }

  condition:
    any of them
}