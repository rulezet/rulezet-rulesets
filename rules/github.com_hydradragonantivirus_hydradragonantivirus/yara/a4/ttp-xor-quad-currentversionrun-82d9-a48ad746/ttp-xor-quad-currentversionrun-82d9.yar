rule TTP_XOR_QUAD_CurrentVersionRun_82d9 {
  strings:
    $key_82d9 = { d1 b6 [2] f5 b8 [2] de 94 [2] f0 b6 [2] e4 ad [2] eb b7 [2] f5 aa [2] f7 ab [2] ec ad [2] f0 aa [2] ec 85 }

  condition:
    any of them
}