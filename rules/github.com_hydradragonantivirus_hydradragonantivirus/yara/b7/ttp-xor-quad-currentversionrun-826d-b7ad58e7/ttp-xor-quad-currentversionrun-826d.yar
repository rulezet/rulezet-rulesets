rule TTP_XOR_QUAD_CurrentVersionRun_826d {
  strings:
    $key_826d = { d1 02 [2] f5 0c [2] de 20 [2] f0 02 [2] e4 19 [2] eb 03 [2] f5 1e [2] f7 1f [2] ec 19 [2] f0 1e [2] ec 31 }

  condition:
    any of them
}