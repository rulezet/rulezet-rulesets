rule TTP_XOR_QUAD_CurrentVersionRun_8116 {
  strings:
    $key_8116 = { d2 79 [2] f6 77 [2] dd 5b [2] f3 79 [2] e7 62 [2] e8 78 [2] f6 65 [2] f4 64 [2] ef 62 [2] f3 65 [2] ef 4a }

  condition:
    any of them
}