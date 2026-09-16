rule TTP_XOR_QUAD_CurrentVersionRun_82fa {
  strings:
    $key_82fa = { d1 95 [2] f5 9b [2] de b7 [2] f0 95 [2] e4 8e [2] eb 94 [2] f5 89 [2] f7 88 [2] ec 8e [2] f0 89 [2] ec a6 }

  condition:
    any of them
}