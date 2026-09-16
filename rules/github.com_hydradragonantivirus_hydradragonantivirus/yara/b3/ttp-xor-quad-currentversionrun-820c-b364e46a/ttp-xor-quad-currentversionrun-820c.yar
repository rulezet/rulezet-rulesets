rule TTP_XOR_QUAD_CurrentVersionRun_820c {
  strings:
    $key_820c = { d1 63 [2] f5 6d [2] de 41 [2] f0 63 [2] e4 78 [2] eb 62 [2] f5 7f [2] f7 7e [2] ec 78 [2] f0 7f [2] ec 50 }

  condition:
    any of them
}