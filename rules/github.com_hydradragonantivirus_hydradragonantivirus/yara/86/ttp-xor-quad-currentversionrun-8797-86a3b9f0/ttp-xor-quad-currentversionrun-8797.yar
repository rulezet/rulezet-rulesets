rule TTP_XOR_QUAD_CurrentVersionRun_8797 {
  strings:
    $key_8797 = { d4 f8 [2] f0 f6 [2] db da [2] f5 f8 [2] e1 e3 [2] ee f9 [2] f0 e4 [2] f2 e5 [2] e9 e3 [2] f5 e4 [2] e9 cb }

  condition:
    any of them
}