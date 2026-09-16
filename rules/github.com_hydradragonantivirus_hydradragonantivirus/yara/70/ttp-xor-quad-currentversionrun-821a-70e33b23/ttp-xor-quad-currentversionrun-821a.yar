rule TTP_XOR_QUAD_CurrentVersionRun_821a {
  strings:
    $key_821a = { d1 75 [2] f5 7b [2] de 57 [2] f0 75 [2] e4 6e [2] eb 74 [2] f5 69 [2] f7 68 [2] ec 6e [2] f0 69 [2] ec 46 }

  condition:
    any of them
}