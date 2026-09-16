rule TTP_XOR_QUAD_CurrentVersionRun_85e9 {
  strings:
    $key_85e9 = { d6 86 [2] f2 88 [2] d9 a4 [2] f7 86 [2] e3 9d [2] ec 87 [2] f2 9a [2] f0 9b [2] eb 9d [2] f7 9a [2] eb b5 }

  condition:
    any of them
}