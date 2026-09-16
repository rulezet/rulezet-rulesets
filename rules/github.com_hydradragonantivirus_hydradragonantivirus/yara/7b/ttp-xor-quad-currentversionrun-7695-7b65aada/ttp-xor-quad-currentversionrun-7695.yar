rule TTP_XOR_QUAD_CurrentVersionRun_7695 {
  strings:
    $key_7695 = { 25 fa [2] 01 f4 [2] 2a d8 [2] 04 fa [2] 10 e1 [2] 1f fb [2] 01 e6 [2] 03 e7 [2] 18 e1 [2] 04 e6 [2] 18 c9 }

  condition:
    any of them
}