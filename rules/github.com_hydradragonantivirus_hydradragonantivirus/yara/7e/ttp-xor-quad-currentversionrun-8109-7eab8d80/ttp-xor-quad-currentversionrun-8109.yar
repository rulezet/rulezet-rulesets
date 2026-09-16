rule TTP_XOR_QUAD_CurrentVersionRun_8109 {
  strings:
    $key_8109 = { d2 66 [2] f6 68 [2] dd 44 [2] f3 66 [2] e7 7d [2] e8 67 [2] f6 7a [2] f4 7b [2] ef 7d [2] f3 7a [2] ef 55 }

  condition:
    any of them
}