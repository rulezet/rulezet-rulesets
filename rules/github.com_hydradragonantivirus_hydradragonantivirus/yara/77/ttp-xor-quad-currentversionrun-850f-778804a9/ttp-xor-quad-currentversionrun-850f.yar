rule TTP_XOR_QUAD_CurrentVersionRun_850f {
  strings:
    $key_850f = { d6 60 [2] f2 6e [2] d9 42 [2] f7 60 [2] e3 7b [2] ec 61 [2] f2 7c [2] f0 7d [2] eb 7b [2] f7 7c [2] eb 53 }

  condition:
    any of them
}