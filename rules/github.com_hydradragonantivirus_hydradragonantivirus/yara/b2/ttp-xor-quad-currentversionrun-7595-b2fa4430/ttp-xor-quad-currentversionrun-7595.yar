rule TTP_XOR_QUAD_CurrentVersionRun_7595 {
  strings:
    $key_7595 = { 26 fa [2] 02 f4 [2] 29 d8 [2] 07 fa [2] 13 e1 [2] 1c fb [2] 02 e6 [2] 00 e7 [2] 1b e1 [2] 07 e6 [2] 1b c9 }

  condition:
    any of them
}