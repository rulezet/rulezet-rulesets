rule TTP_XOR_QUAD_CurrentVersionRun_81d1 {
  strings:
    $key_81d1 = { d2 be [2] f6 b0 [2] dd 9c [2] f3 be [2] e7 a5 [2] e8 bf [2] f6 a2 [2] f4 a3 [2] ef a5 [2] f3 a2 [2] ef 8d }

  condition:
    any of them
}