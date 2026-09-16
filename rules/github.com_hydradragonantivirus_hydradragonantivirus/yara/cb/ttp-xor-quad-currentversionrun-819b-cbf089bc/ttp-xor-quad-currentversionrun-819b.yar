rule TTP_XOR_QUAD_CurrentVersionRun_819b {
  strings:
    $key_819b = { d2 f4 [2] f6 fa [2] dd d6 [2] f3 f4 [2] e7 ef [2] e8 f5 [2] f6 e8 [2] f4 e9 [2] ef ef [2] f3 e8 [2] ef c7 }

  condition:
    any of them
}