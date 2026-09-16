rule TTP_XOR_QUAD_CurrentVersionRun_8132 {
  strings:
    $key_8132 = { d2 5d [2] f6 53 [2] dd 7f [2] f3 5d [2] e7 46 [2] e8 5c [2] f6 41 [2] f4 40 [2] ef 46 [2] f3 41 [2] ef 6e }

  condition:
    any of them
}