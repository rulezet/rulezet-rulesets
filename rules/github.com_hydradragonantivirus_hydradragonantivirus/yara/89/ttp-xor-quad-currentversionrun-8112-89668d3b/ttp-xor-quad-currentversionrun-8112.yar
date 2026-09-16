rule TTP_XOR_QUAD_CurrentVersionRun_8112 {
  strings:
    $key_8112 = { d2 7d [2] f6 73 [2] dd 5f [2] f3 7d [2] e7 66 [2] e8 7c [2] f6 61 [2] f4 60 [2] ef 66 [2] f3 61 [2] ef 4e }

  condition:
    any of them
}