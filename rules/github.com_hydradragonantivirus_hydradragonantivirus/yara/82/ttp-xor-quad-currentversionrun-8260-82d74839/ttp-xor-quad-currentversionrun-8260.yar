rule TTP_XOR_QUAD_CurrentVersionRun_8260 {
  strings:
    $key_8260 = { d1 0f [2] f5 01 [2] de 2d [2] f0 0f [2] e4 14 [2] eb 0e [2] f5 13 [2] f7 12 [2] ec 14 [2] f0 13 [2] ec 3c }

  condition:
    any of them
}