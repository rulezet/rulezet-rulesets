rule TTP_XOR_QUAD_CurrentVersionRun_82fd {
  strings:
    $key_82fd = { d1 92 [2] f5 9c [2] de b0 [2] f0 92 [2] e4 89 [2] eb 93 [2] f5 8e [2] f7 8f [2] ec 89 [2] f0 8e [2] ec a1 }

  condition:
    any of them
}