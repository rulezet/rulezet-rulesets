rule TTP_XOR_QUAD_CurrentVersionRun_8102 {
  strings:
    $key_8102 = { d2 6d [2] f6 63 [2] dd 4f [2] f3 6d [2] e7 76 [2] e8 6c [2] f6 71 [2] f4 70 [2] ef 76 [2] f3 71 [2] ef 5e }

  condition:
    any of them
}