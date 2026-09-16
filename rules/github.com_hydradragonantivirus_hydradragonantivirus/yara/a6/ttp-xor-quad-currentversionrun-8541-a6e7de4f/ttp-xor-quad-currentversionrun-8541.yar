rule TTP_XOR_QUAD_CurrentVersionRun_8541 {
  strings:
    $key_8541 = { d6 2e [2] f2 20 [2] d9 0c [2] f7 2e [2] e3 35 [2] ec 2f [2] f2 32 [2] f0 33 [2] eb 35 [2] f7 32 [2] eb 1d }

  condition:
    any of them
}