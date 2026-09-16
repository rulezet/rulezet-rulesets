rule TTP_XOR_QUAD_CurrentVersionRun_857d {
  strings:
    $key_857d = { d6 12 [2] f2 1c [2] d9 30 [2] f7 12 [2] e3 09 [2] ec 13 [2] f2 0e [2] f0 0f [2] eb 09 [2] f7 0e [2] eb 21 }

  condition:
    any of them
}