rule TTP_XOR_QUAD_CurrentVersionRun_857e {
  strings:
    $key_857e = { d6 11 [2] f2 1f [2] d9 33 [2] f7 11 [2] e3 0a [2] ec 10 [2] f2 0d [2] f0 0c [2] eb 0a [2] f7 0d [2] eb 22 }

  condition:
    any of them
}