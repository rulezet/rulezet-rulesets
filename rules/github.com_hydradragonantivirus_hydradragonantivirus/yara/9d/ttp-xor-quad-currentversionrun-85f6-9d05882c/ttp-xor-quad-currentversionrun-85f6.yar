rule TTP_XOR_QUAD_CurrentVersionRun_85f6 {
  strings:
    $key_85f6 = { d6 99 [2] f2 97 [2] d9 bb [2] f7 99 [2] e3 82 [2] ec 98 [2] f2 85 [2] f0 84 [2] eb 82 [2] f7 85 [2] eb aa }

  condition:
    any of them
}