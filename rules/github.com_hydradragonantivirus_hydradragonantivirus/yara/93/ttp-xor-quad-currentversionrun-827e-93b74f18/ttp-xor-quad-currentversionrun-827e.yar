rule TTP_XOR_QUAD_CurrentVersionRun_827e {
  strings:
    $key_827e = { d1 11 [2] f5 1f [2] de 33 [2] f0 11 [2] e4 0a [2] eb 10 [2] f5 0d [2] f7 0c [2] ec 0a [2] f0 0d [2] ec 22 }

  condition:
    any of them
}