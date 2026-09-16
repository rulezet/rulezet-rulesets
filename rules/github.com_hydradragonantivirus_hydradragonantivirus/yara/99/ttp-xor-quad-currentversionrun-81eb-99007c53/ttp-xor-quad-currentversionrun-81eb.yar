rule TTP_XOR_QUAD_CurrentVersionRun_81eb {
  strings:
    $key_81eb = { d2 84 [2] f6 8a [2] dd a6 [2] f3 84 [2] e7 9f [2] e8 85 [2] f6 98 [2] f4 99 [2] ef 9f [2] f3 98 [2] ef b7 }

  condition:
    any of them
}