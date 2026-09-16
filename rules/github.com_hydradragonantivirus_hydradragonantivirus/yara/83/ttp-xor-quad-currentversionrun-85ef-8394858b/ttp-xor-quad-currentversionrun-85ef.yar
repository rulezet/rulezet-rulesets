rule TTP_XOR_QUAD_CurrentVersionRun_85ef {
  strings:
    $key_85ef = { d6 80 [2] f2 8e [2] d9 a2 [2] f7 80 [2] e3 9b [2] ec 81 [2] f2 9c [2] f0 9d [2] eb 9b [2] f7 9c [2] eb b3 }

  condition:
    any of them
}