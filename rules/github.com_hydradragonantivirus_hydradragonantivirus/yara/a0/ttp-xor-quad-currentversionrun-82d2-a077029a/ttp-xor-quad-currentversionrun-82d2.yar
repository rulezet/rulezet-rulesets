rule TTP_XOR_QUAD_CurrentVersionRun_82d2 {
  strings:
    $key_82d2 = { d1 bd [2] f5 b3 [2] de 9f [2] f0 bd [2] e4 a6 [2] eb bc [2] f5 a1 [2] f7 a0 [2] ec a6 [2] f0 a1 [2] ec 8e }

  condition:
    any of them
}