rule TTP_XOR_QUAD_CurrentVersionRun_854e {
  strings:
    $key_854e = { d6 21 [2] f2 2f [2] d9 03 [2] f7 21 [2] e3 3a [2] ec 20 [2] f2 3d [2] f0 3c [2] eb 3a [2] f7 3d [2] eb 12 }

  condition:
    any of them
}