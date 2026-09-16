rule TTP_XOR_QUAD_CurrentVersionRun_8268 {
  strings:
    $key_8268 = { d1 07 [2] f5 09 [2] de 25 [2] f0 07 [2] e4 1c [2] eb 06 [2] f5 1b [2] f7 1a [2] ec 1c [2] f0 1b [2] ec 34 }

  condition:
    any of them
}