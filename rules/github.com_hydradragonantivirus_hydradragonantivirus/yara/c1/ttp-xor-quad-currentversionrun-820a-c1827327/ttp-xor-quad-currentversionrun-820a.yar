rule TTP_XOR_QUAD_CurrentVersionRun_820a {
  strings:
    $key_820a = { d1 65 [2] f5 6b [2] de 47 [2] f0 65 [2] e4 7e [2] eb 64 [2] f5 79 [2] f7 78 [2] ec 7e [2] f0 79 [2] ec 56 }

  condition:
    any of them
}