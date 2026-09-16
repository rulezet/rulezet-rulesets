rule TTP_XOR_QUAD_CurrentVersionRun_854d {
  strings:
    $key_854d = { d6 22 [2] f2 2c [2] d9 00 [2] f7 22 [2] e3 39 [2] ec 23 [2] f2 3e [2] f0 3f [2] eb 39 [2] f7 3e [2] eb 11 }

  condition:
    any of them
}