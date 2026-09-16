rule TTP_XOR_QUAD_CurrentVersionRun_8249 {
  strings:
    $key_8249 = { d1 26 [2] f5 28 [2] de 04 [2] f0 26 [2] e4 3d [2] eb 27 [2] f5 3a [2] f7 3b [2] ec 3d [2] f0 3a [2] ec 15 }

  condition:
    any of them
}