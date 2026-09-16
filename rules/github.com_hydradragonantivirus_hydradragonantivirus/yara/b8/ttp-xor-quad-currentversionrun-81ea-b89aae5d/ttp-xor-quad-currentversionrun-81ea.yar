rule TTP_XOR_QUAD_CurrentVersionRun_81ea {
  strings:
    $key_81ea = { d2 85 [2] f6 8b [2] dd a7 [2] f3 85 [2] e7 9e [2] e8 84 [2] f6 99 [2] f4 98 [2] ef 9e [2] f3 99 [2] ef b6 }

  condition:
    any of them
}