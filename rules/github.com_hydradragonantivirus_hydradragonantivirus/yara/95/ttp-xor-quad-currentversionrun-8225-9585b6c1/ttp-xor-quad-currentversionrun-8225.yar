rule TTP_XOR_QUAD_CurrentVersionRun_8225 {
  strings:
    $key_8225 = { d1 4a [2] f5 44 [2] de 68 [2] f0 4a [2] e4 51 [2] eb 4b [2] f5 56 [2] f7 57 [2] ec 51 [2] f0 56 [2] ec 79 }

  condition:
    any of them
}