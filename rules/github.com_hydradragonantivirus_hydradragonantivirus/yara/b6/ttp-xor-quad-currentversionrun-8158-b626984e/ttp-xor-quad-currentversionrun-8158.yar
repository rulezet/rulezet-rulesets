rule TTP_XOR_QUAD_CurrentVersionRun_8158 {
  strings:
    $key_8158 = { d2 37 [2] f6 39 [2] dd 15 [2] f3 37 [2] e7 2c [2] e8 36 [2] f6 2b [2] f4 2a [2] ef 2c [2] f3 2b [2] ef 04 }

  condition:
    any of them
}