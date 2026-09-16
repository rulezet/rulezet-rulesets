rule TTP_XOR_QUAD_CurrentVersionRun_8204 {
  strings:
    $key_8204 = { d1 6b [2] f5 65 [2] de 49 [2] f0 6b [2] e4 70 [2] eb 6a [2] f5 77 [2] f7 76 [2] ec 70 [2] f0 77 [2] ec 58 }

  condition:
    any of them
}