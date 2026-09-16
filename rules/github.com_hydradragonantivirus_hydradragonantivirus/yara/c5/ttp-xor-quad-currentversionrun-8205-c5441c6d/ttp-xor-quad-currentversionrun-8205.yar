rule TTP_XOR_QUAD_CurrentVersionRun_8205 {
  strings:
    $key_8205 = { d1 6a [2] f5 64 [2] de 48 [2] f0 6a [2] e4 71 [2] eb 6b [2] f5 76 [2] f7 77 [2] ec 71 [2] f0 76 [2] ec 59 }

  condition:
    any of them
}