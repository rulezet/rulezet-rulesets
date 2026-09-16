rule TTP_XOR_QUAD_CurrentVersionRun_85ea {
  strings:
    $key_85ea = { d6 85 [2] f2 8b [2] d9 a7 [2] f7 85 [2] e3 9e [2] ec 84 [2] f2 99 [2] f0 98 [2] eb 9e [2] f7 99 [2] eb b6 }

  condition:
    any of them
}