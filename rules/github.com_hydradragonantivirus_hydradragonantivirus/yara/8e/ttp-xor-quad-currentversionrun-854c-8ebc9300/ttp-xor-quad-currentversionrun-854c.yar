rule TTP_XOR_QUAD_CurrentVersionRun_854c {
  strings:
    $key_854c = { d6 23 [2] f2 2d [2] d9 01 [2] f7 23 [2] e3 38 [2] ec 22 [2] f2 3f [2] f0 3e [2] eb 38 [2] f7 3f [2] eb 10 }

  condition:
    any of them
}