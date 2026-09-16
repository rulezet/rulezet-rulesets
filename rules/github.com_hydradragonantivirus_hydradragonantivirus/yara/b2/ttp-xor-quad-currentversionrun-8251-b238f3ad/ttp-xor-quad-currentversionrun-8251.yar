rule TTP_XOR_QUAD_CurrentVersionRun_8251 {
  strings:
    $key_8251 = { d1 3e [2] f5 30 [2] de 1c [2] f0 3e [2] e4 25 [2] eb 3f [2] f5 22 [2] f7 23 [2] ec 25 [2] f0 22 [2] ec 0d }

  condition:
    any of them
}