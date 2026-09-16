rule TTP_XOR_QUAD_CurrentVersionRun_81e3 {
  strings:
    $key_81e3 = { d2 8c [2] f6 82 [2] dd ae [2] f3 8c [2] e7 97 [2] e8 8d [2] f6 90 [2] f4 91 [2] ef 97 [2] f3 90 [2] ef bf }

  condition:
    any of them
}