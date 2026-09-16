rule TTP_XOR_QUAD_CurrentVersionRun_8232 {
  strings:
    $key_8232 = { d1 5d [2] f5 53 [2] de 7f [2] f0 5d [2] e4 46 [2] eb 5c [2] f5 41 [2] f7 40 [2] ec 46 [2] f0 41 [2] ec 6e }

  condition:
    any of them
}