rule TTP_XOR_QUAD_CurrentVersionRun_8196 {
  strings:
    $key_8196 = { d2 f9 [2] f6 f7 [2] dd db [2] f3 f9 [2] e7 e2 [2] e8 f8 [2] f6 e5 [2] f4 e4 [2] ef e2 [2] f3 e5 [2] ef ca }

  condition:
    any of them
}