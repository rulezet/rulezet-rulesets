rule TTP_XOR_QUAD_CurrentVersionRun_86c4 {
  strings:
    $key_86c4 = { d5 ab [2] f1 a5 [2] da 89 [2] f4 ab [2] e0 b0 [2] ef aa [2] f1 b7 [2] f3 b6 [2] e8 b0 [2] f4 b7 [2] e8 98 }

  condition:
    any of them
}