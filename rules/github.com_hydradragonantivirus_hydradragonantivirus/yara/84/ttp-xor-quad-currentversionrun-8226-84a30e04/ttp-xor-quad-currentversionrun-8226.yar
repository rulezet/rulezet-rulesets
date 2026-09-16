rule TTP_XOR_QUAD_CurrentVersionRun_8226 {
  strings:
    $key_8226 = { d1 49 [2] f5 47 [2] de 6b [2] f0 49 [2] e4 52 [2] eb 48 [2] f5 55 [2] f7 54 [2] ec 52 [2] f0 55 [2] ec 7a }

  condition:
    any of them
}