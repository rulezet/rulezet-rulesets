rule TTP_XOR_QUAD_CurrentVersionRun_8516 {
  strings:
    $key_8516 = { d6 79 [2] f2 77 [2] d9 5b [2] f7 79 [2] e3 62 [2] ec 78 [2] f2 65 [2] f0 64 [2] eb 62 [2] f7 65 [2] eb 4a }

  condition:
    any of them
}