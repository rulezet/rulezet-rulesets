rule TTP_XOR_QUAD_CurrentVersionRun_82fb {
  strings:
    $key_82fb = { d1 94 [2] f5 9a [2] de b6 [2] f0 94 [2] e4 8f [2] eb 95 [2] f5 88 [2] f7 89 [2] ec 8f [2] f0 88 [2] ec a7 }

  condition:
    any of them
}