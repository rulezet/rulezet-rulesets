rule TTP_XOR_QUAD_CurrentVersionRun_8527 {
  strings:
    $key_8527 = { d6 48 [2] f2 46 [2] d9 6a [2] f7 48 [2] e3 53 [2] ec 49 [2] f2 54 [2] f0 55 [2] eb 53 [2] f7 54 [2] eb 7b }

  condition:
    any of them
}