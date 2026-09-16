rule TTP_XOR_QUAD_CurrentVersionRun_85f8 {
  strings:
    $key_85f8 = { d6 97 [2] f2 99 [2] d9 b5 [2] f7 97 [2] e3 8c [2] ec 96 [2] f2 8b [2] f0 8a [2] eb 8c [2] f7 8b [2] eb a4 }

  condition:
    any of them
}