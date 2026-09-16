rule TTP_XOR_QUAD_CurrentVersionRun_8135 {
  strings:
    $key_8135 = { d2 5a [2] f6 54 [2] dd 78 [2] f3 5a [2] e7 41 [2] e8 5b [2] f6 46 [2] f4 47 [2] ef 41 [2] f3 46 [2] ef 69 }

  condition:
    any of them
}