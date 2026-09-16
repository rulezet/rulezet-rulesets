rule TTP_XOR_QUAD_CurrentVersionRun_857f {
  strings:
    $key_857f = { d6 10 [2] f2 1e [2] d9 32 [2] f7 10 [2] e3 0b [2] ec 11 [2] f2 0c [2] f0 0d [2] eb 0b [2] f7 0c [2] eb 23 }

  condition:
    any of them
}