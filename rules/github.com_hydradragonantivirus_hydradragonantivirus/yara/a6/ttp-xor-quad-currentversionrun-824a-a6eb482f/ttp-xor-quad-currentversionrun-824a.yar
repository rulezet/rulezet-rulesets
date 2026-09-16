rule TTP_XOR_QUAD_CurrentVersionRun_824a {
  strings:
    $key_824a = { d1 25 [2] f5 2b [2] de 07 [2] f0 25 [2] e4 3e [2] eb 24 [2] f5 39 [2] f7 38 [2] ec 3e [2] f0 39 [2] ec 16 }

  condition:
    any of them
}