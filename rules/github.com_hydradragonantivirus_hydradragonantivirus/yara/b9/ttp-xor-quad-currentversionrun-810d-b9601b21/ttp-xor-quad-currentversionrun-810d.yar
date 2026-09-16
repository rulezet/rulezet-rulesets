rule TTP_XOR_QUAD_CurrentVersionRun_810d {
  strings:
    $key_810d = { d2 62 [2] f6 6c [2] dd 40 [2] f3 62 [2] e7 79 [2] e8 63 [2] f6 7e [2] f4 7f [2] ef 79 [2] f3 7e [2] ef 51 }

  condition:
    any of them
}