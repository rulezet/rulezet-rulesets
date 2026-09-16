rule TTP_XOR_QUAD_CurrentVersionRun_852a {
  strings:
    $key_852a = { d6 45 [2] f2 4b [2] d9 67 [2] f7 45 [2] e3 5e [2] ec 44 [2] f2 59 [2] f0 58 [2] eb 5e [2] f7 59 [2] eb 76 }

  condition:
    any of them
}