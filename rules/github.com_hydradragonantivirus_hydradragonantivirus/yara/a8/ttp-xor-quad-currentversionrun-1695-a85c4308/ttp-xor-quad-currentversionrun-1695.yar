rule TTP_XOR_QUAD_CurrentVersionRun_1695 {
  strings:
    $key_1695 = { 45 fa [2] 61 f4 [2] 4a d8 [2] 64 fa [2] 70 e1 [2] 7f fb [2] 61 e6 [2] 63 e7 [2] 78 e1 [2] 64 e6 [2] 78 c9 }

  condition:
    any of them
}