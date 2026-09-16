rule TTP_XOR_QUAD_CurrentVersionRun_81d9 {
  strings:
    $key_81d9 = { d2 b6 [2] f6 b8 [2] dd 94 [2] f3 b6 [2] e7 ad [2] e8 b7 [2] f6 aa [2] f4 ab [2] ef ad [2] f3 aa [2] ef 85 }

  condition:
    any of them
}