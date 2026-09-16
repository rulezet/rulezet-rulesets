rule TTP_XOR_QUAD_CurrentVersionRun_8566 {
  strings:
    $key_8566 = { d6 09 [2] f2 07 [2] d9 2b [2] f7 09 [2] e3 12 [2] ec 08 [2] f2 15 [2] f0 14 [2] eb 12 [2] f7 15 [2] eb 3a }

  condition:
    any of them
}