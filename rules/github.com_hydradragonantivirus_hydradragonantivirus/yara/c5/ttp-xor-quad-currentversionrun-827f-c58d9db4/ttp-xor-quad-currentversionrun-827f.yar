rule TTP_XOR_QUAD_CurrentVersionRun_827f {
  strings:
    $key_827f = { d1 10 [2] f5 1e [2] de 32 [2] f0 10 [2] e4 0b [2] eb 11 [2] f5 0c [2] f7 0d [2] ec 0b [2] f0 0c [2] ec 23 }

  condition:
    any of them
}