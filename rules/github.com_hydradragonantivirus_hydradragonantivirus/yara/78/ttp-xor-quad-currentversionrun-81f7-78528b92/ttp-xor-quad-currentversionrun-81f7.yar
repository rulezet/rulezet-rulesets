rule TTP_XOR_QUAD_CurrentVersionRun_81f7 {
  strings:
    $key_81f7 = { d2 98 [2] f6 96 [2] dd ba [2] f3 98 [2] e7 83 [2] e8 99 [2] f6 84 [2] f4 85 [2] ef 83 [2] f3 84 [2] ef ab }

  condition:
    any of them
}