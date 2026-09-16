rule TTP_XOR_QUAD_CurrentVersionRun_852e {
  strings:
    $key_852e = { d6 41 [2] f2 4f [2] d9 63 [2] f7 41 [2] e3 5a [2] ec 40 [2] f2 5d [2] f0 5c [2] eb 5a [2] f7 5d [2] eb 72 }

  condition:
    any of them
}