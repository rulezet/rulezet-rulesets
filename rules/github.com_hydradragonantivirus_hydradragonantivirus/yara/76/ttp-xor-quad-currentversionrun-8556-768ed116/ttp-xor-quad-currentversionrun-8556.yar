rule TTP_XOR_QUAD_CurrentVersionRun_8556 {
  strings:
    $key_8556 = { d6 39 [2] f2 37 [2] d9 1b [2] f7 39 [2] e3 22 [2] ec 38 [2] f2 25 [2] f0 24 [2] eb 22 [2] f7 25 [2] eb 0a }

  condition:
    any of them
}