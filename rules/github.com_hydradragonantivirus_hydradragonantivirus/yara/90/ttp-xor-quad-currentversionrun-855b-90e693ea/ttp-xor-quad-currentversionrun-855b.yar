rule TTP_XOR_QUAD_CurrentVersionRun_855b {
  strings:
    $key_855b = { d6 34 [2] f2 3a [2] d9 16 [2] f7 34 [2] e3 2f [2] ec 35 [2] f2 28 [2] f0 29 [2] eb 2f [2] f7 28 [2] eb 07 }

  condition:
    any of them
}