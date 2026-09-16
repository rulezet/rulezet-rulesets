rule TTP_XOR_QUAD_CurrentVersionRun_8504 {
  strings:
    $key_8504 = { d6 6b [2] f2 65 [2] d9 49 [2] f7 6b [2] e3 70 [2] ec 6a [2] f2 77 [2] f0 76 [2] eb 70 [2] f7 77 [2] eb 58 }

  condition:
    any of them
}