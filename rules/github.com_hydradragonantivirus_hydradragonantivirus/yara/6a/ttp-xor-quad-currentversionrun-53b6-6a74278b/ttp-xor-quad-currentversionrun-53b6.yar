rule TTP_XOR_QUAD_CurrentVersionRun_53b6 {
  strings:
    $key_53b6 = { 00 d9 [2] 24 d7 [2] 0f fb [2] 21 d9 [2] 35 c2 [2] 3a d8 [2] 24 c5 [2] 26 c4 [2] 3d c2 [2] 21 c5 [2] 3d ea }

  condition:
    any of them
}