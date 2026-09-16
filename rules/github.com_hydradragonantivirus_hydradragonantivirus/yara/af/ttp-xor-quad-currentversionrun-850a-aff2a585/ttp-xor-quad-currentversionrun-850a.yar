rule TTP_XOR_QUAD_CurrentVersionRun_850a {
  strings:
    $key_850a = { d6 65 [2] f2 6b [2] d9 47 [2] f7 65 [2] e3 7e [2] ec 64 [2] f2 79 [2] f0 78 [2] eb 7e [2] f7 79 [2] eb 56 }

  condition:
    any of them
}