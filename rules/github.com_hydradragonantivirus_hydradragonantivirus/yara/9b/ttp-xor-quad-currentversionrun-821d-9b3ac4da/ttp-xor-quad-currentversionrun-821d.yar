rule TTP_XOR_QUAD_CurrentVersionRun_821d {
  strings:
    $key_821d = { d1 72 [2] f5 7c [2] de 50 [2] f0 72 [2] e4 69 [2] eb 73 [2] f5 6e [2] f7 6f [2] ec 69 [2] f0 6e [2] ec 41 }

  condition:
    any of them
}