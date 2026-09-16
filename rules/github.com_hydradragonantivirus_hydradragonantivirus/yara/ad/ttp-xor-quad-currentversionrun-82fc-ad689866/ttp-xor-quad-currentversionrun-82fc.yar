rule TTP_XOR_QUAD_CurrentVersionRun_82fc {
  strings:
    $key_82fc = { d1 93 [2] f5 9d [2] de b1 [2] f0 93 [2] e4 88 [2] eb 92 [2] f5 8f [2] f7 8e [2] ec 88 [2] f0 8f [2] ec a0 }

  condition:
    any of them
}