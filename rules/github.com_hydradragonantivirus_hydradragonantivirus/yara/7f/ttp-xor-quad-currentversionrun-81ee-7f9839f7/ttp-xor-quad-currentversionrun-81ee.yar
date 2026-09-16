rule TTP_XOR_QUAD_CurrentVersionRun_81ee {
  strings:
    $key_81ee = { d2 81 [2] f6 8f [2] dd a3 [2] f3 81 [2] e7 9a [2] e8 80 [2] f6 9d [2] f4 9c [2] ef 9a [2] f3 9d [2] ef b2 }

  condition:
    any of them
}