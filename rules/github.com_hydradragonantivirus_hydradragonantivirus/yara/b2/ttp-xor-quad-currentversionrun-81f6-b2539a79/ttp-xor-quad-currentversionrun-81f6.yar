rule TTP_XOR_QUAD_CurrentVersionRun_81f6 {
  strings:
    $key_81f6 = { d2 99 [2] f6 97 [2] dd bb [2] f3 99 [2] e7 82 [2] e8 98 [2] f6 85 [2] f4 84 [2] ef 82 [2] f3 85 [2] ef aa }

  condition:
    any of them
}