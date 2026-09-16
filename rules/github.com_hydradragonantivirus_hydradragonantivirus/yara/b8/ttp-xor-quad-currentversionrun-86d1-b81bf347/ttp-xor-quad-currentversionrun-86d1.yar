rule TTP_XOR_QUAD_CurrentVersionRun_86d1 {
  strings:
    $key_86d1 = { d5 be [2] f1 b0 [2] da 9c [2] f4 be [2] e0 a5 [2] ef bf [2] f1 a2 [2] f3 a3 [2] e8 a5 [2] f4 a2 [2] e8 8d }

  condition:
    any of them
}