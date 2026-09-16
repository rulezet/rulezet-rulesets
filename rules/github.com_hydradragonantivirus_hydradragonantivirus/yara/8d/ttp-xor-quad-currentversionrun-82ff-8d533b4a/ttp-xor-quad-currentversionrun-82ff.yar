rule TTP_XOR_QUAD_CurrentVersionRun_82ff {
  strings:
    $key_82ff = { d1 90 [2] f5 9e [2] de b2 [2] f0 90 [2] e4 8b [2] eb 91 [2] f5 8c [2] f7 8d [2] ec 8b [2] f0 8c [2] ec a3 }

  condition:
    any of them
}