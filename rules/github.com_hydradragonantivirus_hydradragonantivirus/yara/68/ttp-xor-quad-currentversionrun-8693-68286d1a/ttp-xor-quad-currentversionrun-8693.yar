rule TTP_XOR_QUAD_CurrentVersionRun_8693 {
  strings:
    $key_8693 = { d5 fc [2] f1 f2 [2] da de [2] f4 fc [2] e0 e7 [2] ef fd [2] f1 e0 [2] f3 e1 [2] e8 e7 [2] f4 e0 [2] e8 cf }

  condition:
    any of them
}