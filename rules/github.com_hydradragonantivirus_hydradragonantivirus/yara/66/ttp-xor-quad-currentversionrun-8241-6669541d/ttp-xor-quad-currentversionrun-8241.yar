rule TTP_XOR_QUAD_CurrentVersionRun_8241 {
  strings:
    $key_8241 = { d1 2e [2] f5 20 [2] de 0c [2] f0 2e [2] e4 35 [2] eb 2f [2] f5 32 [2] f7 33 [2] ec 35 [2] f0 32 [2] ec 1d }

  condition:
    any of them
}