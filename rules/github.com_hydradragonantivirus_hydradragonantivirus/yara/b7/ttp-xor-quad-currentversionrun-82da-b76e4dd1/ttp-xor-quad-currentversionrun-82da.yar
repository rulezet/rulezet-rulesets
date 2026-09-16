rule TTP_XOR_QUAD_CurrentVersionRun_82da {
  strings:
    $key_82da = { d1 b5 [2] f5 bb [2] de 97 [2] f0 b5 [2] e4 ae [2] eb b4 [2] f5 a9 [2] f7 a8 [2] ec ae [2] f0 a9 [2] ec 86 }

  condition:
    any of them
}