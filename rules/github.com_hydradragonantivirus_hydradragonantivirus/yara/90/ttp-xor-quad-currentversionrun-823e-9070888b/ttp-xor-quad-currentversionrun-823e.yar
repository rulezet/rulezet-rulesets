rule TTP_XOR_QUAD_CurrentVersionRun_823e {
  strings:
    $key_823e = { d1 51 [2] f5 5f [2] de 73 [2] f0 51 [2] e4 4a [2] eb 50 [2] f5 4d [2] f7 4c [2] ec 4a [2] f0 4d [2] ec 62 }

  condition:
    any of them
}