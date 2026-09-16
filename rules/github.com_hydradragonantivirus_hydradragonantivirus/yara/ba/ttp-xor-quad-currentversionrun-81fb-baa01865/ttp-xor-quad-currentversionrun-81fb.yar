rule TTP_XOR_QUAD_CurrentVersionRun_81fb {
  strings:
    $key_81fb = { d2 94 [2] f6 9a [2] dd b6 [2] f3 94 [2] e7 8f [2] e8 95 [2] f6 88 [2] f4 89 [2] ef 8f [2] f3 88 [2] ef a7 }

  condition:
    any of them
}