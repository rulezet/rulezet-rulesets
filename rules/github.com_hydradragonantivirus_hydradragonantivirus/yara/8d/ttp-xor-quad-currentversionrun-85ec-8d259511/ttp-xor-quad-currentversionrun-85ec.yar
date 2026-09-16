rule TTP_XOR_QUAD_CurrentVersionRun_85ec {
  strings:
    $key_85ec = { d6 83 [2] f2 8d [2] d9 a1 [2] f7 83 [2] e3 98 [2] ec 82 [2] f2 9f [2] f0 9e [2] eb 98 [2] f7 9f [2] eb b0 }

  condition:
    any of them
}