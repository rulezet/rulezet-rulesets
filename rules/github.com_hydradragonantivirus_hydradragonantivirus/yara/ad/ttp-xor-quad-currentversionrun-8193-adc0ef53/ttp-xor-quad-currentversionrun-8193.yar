rule TTP_XOR_QUAD_CurrentVersionRun_8193 {
  strings:
    $key_8193 = { d2 fc [2] f6 f2 [2] dd de [2] f3 fc [2] e7 e7 [2] e8 fd [2] f6 e0 [2] f4 e1 [2] ef e7 [2] f3 e0 [2] ef cf }

  condition:
    any of them
}