rule TTP_XOR_QUAD_CurrentVersionRun_823a {
  strings:
    $key_823a = { d1 55 [2] f5 5b [2] de 77 [2] f0 55 [2] e4 4e [2] eb 54 [2] f5 49 [2] f7 48 [2] ec 4e [2] f0 49 [2] ec 66 }

  condition:
    any of them
}