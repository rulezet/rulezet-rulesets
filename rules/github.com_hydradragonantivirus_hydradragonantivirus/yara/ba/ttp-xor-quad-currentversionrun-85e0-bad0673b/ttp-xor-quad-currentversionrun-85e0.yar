rule TTP_XOR_QUAD_CurrentVersionRun_85e0 {
  strings:
    $key_85e0 = { d6 8f [2] f2 81 [2] d9 ad [2] f7 8f [2] e3 94 [2] ec 8e [2] f2 93 [2] f0 92 [2] eb 94 [2] f7 93 [2] eb bc }

  condition:
    any of them
}