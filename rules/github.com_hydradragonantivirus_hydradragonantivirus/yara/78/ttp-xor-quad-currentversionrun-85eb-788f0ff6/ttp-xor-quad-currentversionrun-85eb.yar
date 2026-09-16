rule TTP_XOR_QUAD_CurrentVersionRun_85eb {
  strings:
    $key_85eb = { d6 84 [2] f2 8a [2] d9 a6 [2] f7 84 [2] e3 9f [2] ec 85 [2] f2 98 [2] f0 99 [2] eb 9f [2] f7 98 [2] eb b7 }

  condition:
    any of them
}