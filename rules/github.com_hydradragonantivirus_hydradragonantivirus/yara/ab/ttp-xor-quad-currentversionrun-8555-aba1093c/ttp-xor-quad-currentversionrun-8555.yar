rule TTP_XOR_QUAD_CurrentVersionRun_8555 {
  strings:
    $key_8555 = { d6 3a [2] f2 34 [2] d9 18 [2] f7 3a [2] e3 21 [2] ec 3b [2] f2 26 [2] f0 27 [2] eb 21 [2] f7 26 [2] eb 09 }

  condition:
    any of them
}