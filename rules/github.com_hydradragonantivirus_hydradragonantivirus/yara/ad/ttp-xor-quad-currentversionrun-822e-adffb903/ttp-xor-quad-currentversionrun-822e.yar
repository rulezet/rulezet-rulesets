rule TTP_XOR_QUAD_CurrentVersionRun_822e {
  strings:
    $key_822e = { d1 41 [2] f5 4f [2] de 63 [2] f0 41 [2] e4 5a [2] eb 40 [2] f5 5d [2] f7 5c [2] ec 5a [2] f0 5d [2] ec 72 }

  condition:
    any of them
}