rule TTP_XOR_QUAD_CurrentVersionRun_81e6 {
  strings:
    $key_81e6 = { d2 89 [2] f6 87 [2] dd ab [2] f3 89 [2] e7 92 [2] e8 88 [2] f6 95 [2] f4 94 [2] ef 92 [2] f3 95 [2] ef ba }

  condition:
    any of them
}