rule TTP_XOR_QUAD_CurrentVersionRun_821e {
  strings:
    $key_821e = { d1 71 [2] f5 7f [2] de 53 [2] f0 71 [2] e4 6a [2] eb 70 [2] f5 6d [2] f7 6c [2] ec 6a [2] f0 6d [2] ec 42 }

  condition:
    any of them
}