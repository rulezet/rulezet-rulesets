rule TTP_XOR_QUAD_CurrentVersionRun_86d8 {
  strings:
    $key_86d8 = { d5 b7 [2] f1 b9 [2] da 95 [2] f4 b7 [2] e0 ac [2] ef b6 [2] f1 ab [2] f3 aa [2] e8 ac [2] f4 ab [2] e8 84 }

  condition:
    any of them
}