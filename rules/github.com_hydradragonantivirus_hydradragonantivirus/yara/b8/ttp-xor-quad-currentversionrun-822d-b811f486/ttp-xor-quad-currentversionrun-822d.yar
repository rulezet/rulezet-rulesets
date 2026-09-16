rule TTP_XOR_QUAD_CurrentVersionRun_822d {
  strings:
    $key_822d = { d1 42 [2] f5 4c [2] de 60 [2] f0 42 [2] e4 59 [2] eb 43 [2] f5 5e [2] f7 5f [2] ec 59 [2] f0 5e [2] ec 71 }

  condition:
    any of them
}