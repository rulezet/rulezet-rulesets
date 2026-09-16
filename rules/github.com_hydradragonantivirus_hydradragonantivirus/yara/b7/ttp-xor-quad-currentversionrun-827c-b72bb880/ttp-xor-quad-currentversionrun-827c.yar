rule TTP_XOR_QUAD_CurrentVersionRun_827c {
  strings:
    $key_827c = { d1 13 [2] f5 1d [2] de 31 [2] f0 13 [2] e4 08 [2] eb 12 [2] f5 0f [2] f7 0e [2] ec 08 [2] f0 0f [2] ec 20 }

  condition:
    any of them
}