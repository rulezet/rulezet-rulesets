rule TTP_XOR_QUAD_CurrentVersionRun_813b {
  strings:
    $key_813b = { d2 54 [2] f6 5a [2] dd 76 [2] f3 54 [2] e7 4f [2] e8 55 [2] f6 48 [2] f4 49 [2] ef 4f [2] f3 48 [2] ef 67 }

  condition:
    any of them
}