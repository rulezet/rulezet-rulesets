rule TTP_XOR_QUAD_CurrentVersionRun_8273 {
  strings:
    $key_8273 = { d1 1c [2] f5 12 [2] de 3e [2] f0 1c [2] e4 07 [2] eb 1d [2] f5 00 [2] f7 01 [2] ec 07 [2] f0 00 [2] ec 2f }

  condition:
    any of them
}