rule TTP_XOR_QUAD_CurrentVersionRun_82d1 {
  strings:
    $key_82d1 = { d1 be [2] f5 b0 [2] de 9c [2] f0 be [2] e4 a5 [2] eb bf [2] f5 a2 [2] f7 a3 [2] ec a5 [2] f0 a2 [2] ec 8d }

  condition:
    any of them
}