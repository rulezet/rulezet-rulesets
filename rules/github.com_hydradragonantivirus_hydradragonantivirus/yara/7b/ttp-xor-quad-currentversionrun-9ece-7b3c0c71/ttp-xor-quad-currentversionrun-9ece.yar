rule TTP_XOR_QUAD_CurrentVersionRun_9ece {
  strings:
    $key_9ece = { cd a1 [2] e9 af [2] c2 83 [2] ec a1 [2] f8 ba [2] f7 a0 [2] e9 bd [2] eb bc [2] f0 ba [2] ec bd [2] f0 92 }

  condition:
    any of them
}