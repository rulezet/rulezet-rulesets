rule TTP_XOR_QUAD_CurrentVersionRun_850e {
  strings:
    $key_850e = { d6 61 [2] f2 6f [2] d9 43 [2] f7 61 [2] e3 7a [2] ec 60 [2] f2 7d [2] f0 7c [2] eb 7a [2] f7 7d [2] eb 52 }

  condition:
    any of them
}