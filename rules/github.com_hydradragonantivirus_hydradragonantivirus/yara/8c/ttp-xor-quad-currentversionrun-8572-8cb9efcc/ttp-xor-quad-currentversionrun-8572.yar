rule TTP_XOR_QUAD_CurrentVersionRun_8572 {
  strings:
    $key_8572 = { d6 1d [2] f2 13 [2] d9 3f [2] f7 1d [2] e3 06 [2] ec 1c [2] f2 01 [2] f0 00 [2] eb 06 [2] f7 01 [2] eb 2e }

  condition:
    any of them
}