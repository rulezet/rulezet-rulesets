rule TTP_XOR_QUAD_CurrentVersionRun_8561 {
  strings:
    $key_8561 = { d6 0e [2] f2 00 [2] d9 2c [2] f7 0e [2] e3 15 [2] ec 0f [2] f2 12 [2] f0 13 [2] eb 15 [2] f7 12 [2] eb 3d }

  condition:
    any of them
}