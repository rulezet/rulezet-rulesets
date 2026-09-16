rule TTP_XOR_QUAD_CurrentVersionRun_82d7 {
  strings:
    $key_82d7 = { d1 b8 [2] f5 b6 [2] de 9a [2] f0 b8 [2] e4 a3 [2] eb b9 [2] f5 a4 [2] f7 a5 [2] ec a3 [2] f0 a4 [2] ec 8b }

  condition:
    any of them
}