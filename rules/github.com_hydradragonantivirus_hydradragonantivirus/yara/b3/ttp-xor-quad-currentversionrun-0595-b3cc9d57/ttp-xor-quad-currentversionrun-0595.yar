rule TTP_XOR_QUAD_CurrentVersionRun_0595 {
  strings:
    $key_0595 = { 56 fa [2] 72 f4 [2] 59 d8 [2] 77 fa [2] 63 e1 [2] 6c fb [2] 72 e6 [2] 70 e7 [2] 6b e1 [2] 77 e6 [2] 6b c9 }

  condition:
    any of them
}