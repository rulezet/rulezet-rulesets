rule TTP_XOR_QUAD_CurrentVersionRun_8526 {
  strings:
    $key_8526 = { d6 49 [2] f2 47 [2] d9 6b [2] f7 49 [2] e3 52 [2] ec 48 [2] f2 55 [2] f0 54 [2] eb 52 [2] f7 55 [2] eb 7a }

  condition:
    any of them
}