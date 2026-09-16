rule TTP_XOR_QUAD_CurrentVersionRun_aece {
  strings:
    $key_aece = { fd a1 [2] d9 af [2] f2 83 [2] dc a1 [2] c8 ba [2] c7 a0 [2] d9 bd [2] db bc [2] c0 ba [2] dc bd [2] c0 92 }

  condition:
    any of them
}