rule TTP_XOR_QUAD_CurrentVersionRun_851e {
  strings:
    $key_851e = { d6 71 [2] f2 7f [2] d9 53 [2] f7 71 [2] e3 6a [2] ec 70 [2] f2 6d [2] f0 6c [2] eb 6a [2] f7 6d [2] eb 42 }

  condition:
    any of them
}