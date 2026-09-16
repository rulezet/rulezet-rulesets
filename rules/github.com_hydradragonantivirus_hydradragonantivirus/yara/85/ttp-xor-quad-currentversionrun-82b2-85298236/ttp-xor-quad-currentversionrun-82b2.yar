rule TTP_XOR_QUAD_CurrentVersionRun_82b2 {
  strings:
    $key_82b2 = { d1 dd [2] f5 d3 [2] de ff [2] f0 dd [2] e4 c6 [2] eb dc [2] f5 c1 [2] f7 c0 [2] ec c6 [2] f0 c1 [2] ec ee }

  condition:
    any of them
}