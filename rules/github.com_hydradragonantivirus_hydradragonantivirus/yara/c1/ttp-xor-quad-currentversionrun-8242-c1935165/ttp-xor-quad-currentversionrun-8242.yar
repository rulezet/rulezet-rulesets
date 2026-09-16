rule TTP_XOR_QUAD_CurrentVersionRun_8242 {
  strings:
    $key_8242 = { d1 2d [2] f5 23 [2] de 0f [2] f0 2d [2] e4 36 [2] eb 2c [2] f5 31 [2] f7 30 [2] ec 36 [2] f0 31 [2] ec 1e }

  condition:
    any of them
}