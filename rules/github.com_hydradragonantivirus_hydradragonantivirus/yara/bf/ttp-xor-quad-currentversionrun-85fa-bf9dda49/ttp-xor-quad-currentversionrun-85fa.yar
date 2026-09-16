rule TTP_XOR_QUAD_CurrentVersionRun_85fa {
  strings:
    $key_85fa = { d6 95 [2] f2 9b [2] d9 b7 [2] f7 95 [2] e3 8e [2] ec 94 [2] f2 89 [2] f0 88 [2] eb 8e [2] f7 89 [2] eb a6 }

  condition:
    any of them
}